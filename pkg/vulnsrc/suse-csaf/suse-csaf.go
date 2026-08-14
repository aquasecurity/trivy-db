package susecsaf

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/samber/lo"
	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/go-version/pkg/version"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

type Distribution int

const (
	SUSEEnterpriseLinux Distribution = iota
	SUSEEnterpriseLinuxMicro
	OpenSUSE
	OpenSUSETumbleweed

	vulnListDir = "vuln-list-suse"
	csafDir     = "csaf/suse"
)

var (
	source = types.DataSource{
		ID:   vulnerability.SuseCSAF,
		Name: "SUSE CSAF",
		URL:  "https://ftp.suse.com/pub/projects/security/csaf/",
	}
	// cvrfSource keeps severitySource/primaryURL stable for existing Trivy releases during migration.
	cvrfSource = types.DataSource{
		ID:   vulnerability.SuseCVRF,
		Name: "SUSE CVRF",
		URL:  "https://ftp.suse.com/pub/projects/security/cvrf/",
	}
)

type PutInput struct {
	VulnID string

	// Advisory is the CSAF document the other fields were derived from.
	Advisory csaf.Advisory

	Vuln         types.VulnerabilityDetail
	AffectedPkgs []AffectedPackage
}

type DB interface {
	db.Operation
	Put(tx *bolt.Tx, input PutInput) error
}

type VulnSrc struct {
	DB
	dist   Distribution
	logger *log.Logger
}

type Suse struct {
	db.Operation
}

func NewVulnSrc(dist Distribution) VulnSrc {
	return VulnSrc{
		DB:     &Suse{Operation: db.Config{}},
		dist:   dist,
		logger: log.WithPrefix("suse-csaf"),
	}
}

func (vs VulnSrc) Name() types.SourceID {
	if vs.dist == OpenSUSE {
		return "opensuse-csaf"
	}
	if vs.dist == OpenSUSETumbleweed {
		return "opensuse-tumbleweed-csaf"
	}
	return source.ID
}

func (vs VulnSrc) Update(dir string) error {
	vs.logger.Info("Saving SUSE CSAF")
	rootDir := filepath.Join(dir, vulnListDir, csafDir)
	eb := oops.In("suse").Tags("csaf").With("root_dir", rootDir)

	switch vs.dist {
	case SUSEEnterpriseLinux, SUSEEnterpriseLinuxMicro:
		rootDir = filepath.Join(rootDir, "suse")
	case OpenSUSE, OpenSUSETumbleweed:
		rootDir = filepath.Join(rootDir, "opensuse")
	default:
		return eb.Errorf("unknown distribution")
	}

	err := vs.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.walk(tx, rootDir)
	})
	if err != nil {
		return eb.Wrapf(err, "batch update error")
	}

	return nil
}

// walk writes each advisory to the database as soon as it is decoded, so only one
// CSAF document is held in memory at a time.
func (vs VulnSrc) walk(tx *bolt.Tx, rootDir string) error {
	savedDataSources := make(map[string]struct{})

	return utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		eb := oops.With("file_path", path)

		var adv csaf.Advisory
		if err := json.NewDecoder(r).Decode(&adv); err != nil {
			return eb.Wrapf(err, "json decode error")
		}

		if err := vs.commit(tx, adv, savedDataSources); err != nil {
			return eb.Wrapf(err, "commit error")
		}
		return nil
	})
}

// buildInput extracts the values written to the database from a CSAF document.
func (vs VulnSrc) buildInput(adv csaf.Advisory) (PutInput, error) {
	doc := lo.FromPtr(adv.Document)
	vulnID := string(lo.FromPtr(lo.FromPtr(doc.Tracking).ID))
	if vulnID == "" {
		return PutInput{}, errors.New("missing tracking id")
	}

	references := make([]string, 0, len(doc.References))
	for _, ref := range doc.References {
		if ref == nil {
			continue
		}
		references = append(references, lo.FromPtr(ref.URL))
	}

	return PutInput{
		VulnID:   vulnID,
		Advisory: adv,
		Vuln: types.VulnerabilityDetail{
			References:  references,
			Title:       lo.FromPtr(doc.Title),
			Description: description(doc.Notes),
			Severity:    severityFromAdvisory(&doc, adv.Vulnerabilities),
		},
		AffectedPkgs: vs.getAffectedPackages(
			lo.FromPtr(lo.FromPtr(adv.ProductTree).RelationShips),
			adv.Vulnerabilities,
		),
	}, nil
}

// description returns the text of the "description" note, which SUSE uses for the advisory body.
func description(notes csaf.Notes) string {
	for _, n := range notes {
		if n != nil && lo.FromPtr(n.NoteCategory) == csaf.CSAFNoteCategoryDescription {
			return lo.FromPtr(n.Text)
		}
	}
	return ""
}

// severityFromAdvisory prefers per-CVE impact threats and falls back to document.aggregate_severity.
func severityFromAdvisory(doc *csaf.Document, vulns csaf.Vulnerabilities) types.Severity {
	if sev := highestImpact(vulns); sev != types.SeverityUnknown {
		return sev
	}
	if doc != nil && doc.AggregateSeverity != nil {
		return severityFromThreat(lo.FromPtr(doc.AggregateSeverity.Text))
	}
	return types.SeverityUnknown
}

// highestImpact returns the most severe impact rating across all vulnerabilities in the advisory.
func highestImpact(vulns csaf.Vulnerabilities) types.Severity {
	severity := types.SeverityUnknown
	for _, vuln := range vulns {
		if vuln == nil {
			continue
		}
		for _, threat := range vuln.Threats {
			if threat == nil || lo.FromPtr(threat.Category) != csaf.CSAFThreatCategoryImpact {
				continue
			}
			if sev := severityFromThreat(lo.FromPtr(threat.Details)); severity < sev {
				severity = sev
			}
		}
	}
	return severity
}

func allowedProductIDs(vulns csaf.Vulnerabilities) (map[string]struct{}, bool) {
	allowed := make(map[string]struct{})
	hasStatus := false
	for _, vuln := range vulns {
		if vuln == nil || vuln.ProductStatus == nil {
			continue
		}
		for _, products := range []*csaf.Products{vuln.ProductStatus.Fixed, vuln.ProductStatus.Recommended} {
			if products == nil {
				continue
			}
			hasStatus = true
			for _, pid := range *products {
				if pid == nil {
					continue
				}
				allowed[string(*pid)] = struct{}{}
			}
		}
	}
	return allowed, hasStatus
}

// commit writes a single advisory. savedDataSources is shared across the whole walk so
// that each OS version's data source is written only once.
func (vs VulnSrc) commit(tx *bolt.Tx, adv csaf.Advisory, savedDataSources map[string]struct{}) error {
	input, err := vs.buildInput(adv)
	if err != nil {
		return oops.Wrapf(err, "invalid advisory")
	}
	if len(input.AffectedPkgs) == 0 {
		return nil
	}

	eb := oops.With("tracking_id", input.VulnID)
	for _, affectedPkg := range input.AffectedPkgs {
		if _, ok := savedDataSources[affectedPkg.OSVer]; ok {
			continue
		}

		if err := vs.PutDataSource(tx, affectedPkg.OSVer, cvrfSource); err != nil {
			return eb.Wrapf(err, "failed to put data source")
		}
		savedDataSources[affectedPkg.OSVer] = struct{}{}
	}

	if err := vs.Put(tx, input); err != nil {
		return eb.Wrapf(err, "Put error")
	}
	return nil
}

func (vs *Suse) Put(tx *bolt.Tx, input PutInput) error {
	for _, affectedPkg := range input.AffectedPkgs {
		advisory := types.Advisory{
			FixedVersion: affectedPkg.Package.FixedVersion,
		}

		if err := vs.PutAdvisoryDetail(tx, input.VulnID, affectedPkg.Package.Name,
			[]string{affectedPkg.OSVer}, advisory); err != nil {
			return oops.Wrapf(err, "unable to save CSAF advisory")
		}
	}

	if err := vs.PutVulnerabilityDetail(tx, input.VulnID, cvrfSource.ID, input.Vuln); err != nil {
		return oops.With("tracking_id", input.VulnID).Wrapf(err, "failed to save SUSE CSAF vulnerability")
	}

	if err := vs.PutVulnerabilityID(tx, input.VulnID); err != nil {
		return oops.With("tracking_id", input.VulnID).Wrapf(err, "failed to save the vulnerability ID")
	}
	return nil
}

func (vs VulnSrc) getAffectedPackages(relationships csaf.Relationships, vulns csaf.Vulnerabilities) []AffectedPackage {
	allowed, filter := allowedProductIDs(vulns)
	seen := make(map[string]struct{})
	var pkgs []AffectedPackage

	for _, relationship := range relationships {
		if relationship == nil {
			continue
		}

		platform := string(lo.FromPtr(relationship.RelatesToProductReference))
		productRef := string(lo.FromPtr(relationship.ProductReference))
		if filter {
			productID := platform + ":" + productRef
			if _, ok := allowed[productID]; !ok {
				continue
			}
		}

		osVer := vs.getOSVersion(platform)
		if osVer == "" {
			continue
		}

		pkg := getPackage(stripArchSuffix(productRef))
		if pkg == nil {
			vs.logger.Warn("Invalid package name", log.String("reference", productRef))
			continue
		}

		key := osVer + "\x00" + pkg.Name + "\x00" + pkg.FixedVersion
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		pkgs = append(pkgs, AffectedPackage{
			OSVer:   osVer,
			Package: *pkg,
		})
	}

	return pkgs
}

//nolint:gocyclo
func (vs VulnSrc) getOSVersion(platformName string) string {
	if strings.Contains(platformName, "SUSE Manager") {
		return ""
	}
	if strings.HasPrefix(platformName, "openSUSE Tumbleweed") {
		return bucket.NewOpenSUSETumbleweed().Name()
	}
	if strings.HasPrefix(platformName, "openSUSE Leap Micro") {
		ss := strings.Fields(platformName)
		if len(ss) < 4 {
			vs.logger.Warn("Invalid version", log.String("platform", platformName))
			return ""
		}

		if _, err := version.Parse(ss[3]); err != nil {
			vs.logger.Warn("Invalid version", log.String("platform", platformName), log.Err(err))
			return ""
		}

		return bucket.NewOpenSUSELeapMicro(ss[3]).Name()
	}
	if strings.HasPrefix(platformName, "openSUSE Leap") {
		ss := strings.Split(platformName, " ")
		if len(ss) < 3 {
			vs.logger.Warn("Invalid version", log.String("platform", platformName))
			return ""
		}
		if _, err := version.Parse(ss[2]); err != nil {
			vs.logger.Warn("Invalid version",
				log.String("platform", platformName),
				log.Err(err))
			return ""
		}
		return bucket.NewOpenSUSE(ss[2]).Name()
	}
	if strings.HasPrefix(platformName, "SUSE Linux Enterprise Micro") {
		ss := strings.Split(platformName, " ")
		if len(ss) < 5 {
			vs.logger.Warn("Invalid version", log.String("platform", platformName))
			return ""
		}
		if _, err := version.Parse(ss[4]); err != nil {
			vs.logger.Warn("Invalid version",
				log.String("platform", platformName),
				log.Err(err))
			return ""
		}
		return bucket.NewSUSELinuxEnterpriseMicro(ss[4]).Name()
	}
	if strings.HasPrefix(platformName, "SUSE Linux Micro") {
		ss := strings.Split(platformName, " ")
		if len(ss) < 4 {
			vs.logger.Warn("Invalid version", log.String("platform", platformName))
			return ""
		}
		if _, err := version.Parse(ss[3]); err != nil {
			vs.logger.Warn("Invalid version",
				log.String("platform", platformName),
				log.Err(err))
			return ""
		}
		return bucket.NewSUSELinuxEnterpriseMicro(ss[3]).Name()
	}
	if strings.Contains(platformName, "SUSE Linux Enterprise") {
		if strings.HasPrefix(platformName, "SUSE Linux Enterprise Storage") {
			return ""
		}

		ss := strings.Fields(strings.ReplaceAll(strings.ReplaceAll(platformName, "-", " "), ".", " "))
		versions := make([]string, 0, 2)
		for i := len(ss) - 1; i > 0; i-- {
			v, err := strconv.Atoi(strings.TrimPrefix(ss[i], "SP"))
			if err != nil {
				continue
			}
			versions = append(versions, strconv.Itoa(v))
			if len(versions) == 2 {
				break
			}
		}
		switch len(versions) {
		case 0:
			vs.logger.Warn("Failed to detect version", log.String("platform", platformName))
			return ""
		case 1:
			return bucket.NewSUSELinuxEnterprise(versions[0]).Name()
		case 2:
			return bucket.NewSUSELinuxEnterprise(fmt.Sprintf("%s.%s", versions[1], versions[0])).Name()
		}
	}

	return ""
}

func getPackage(packVer string) *Package {
	name, ver := splitPkgName(packVer)
	if name == "" {
		return nil
	}
	return &Package{
		Name:         name,
		FixedVersion: ver,
	}
}

// reference: https://github.com/aquasecurity/trivy-db/blob/5c844be3ba6b9ef13df640857a10f8737e360feb/pkg/vulnsrc/redhat/redhat.go#L196-L217
func splitPkgName(pkgName string) (string, string) {
	var ver string

	index := strings.LastIndex(pkgName, "-")
	if index == -1 {
		return "", ""
	}
	ver = pkgName[index:]
	pkgName = pkgName[:index]

	index = strings.LastIndex(pkgName, "-")
	if index == -1 {
		return "", ""
	}
	ver = pkgName[index+1:] + ver
	pkgName = pkgName[:index]

	return pkgName, ver
}

func stripArchSuffix(ref string) string {
	archSuffixes := []string{
		".aarch64_ilp32", ".x86_64", ".aarch64", ".ppc64le", ".s390x", ".i586", ".ia64",
		".riscv64", ".armv7hl", ".armv7l", ".ppc64", ".arm64", ".noarch", ".i686", ".ppc", ".s390",
	}
	for _, sfx := range archSuffixes {
		if strings.HasSuffix(ref, sfx) {
			return strings.TrimSuffix(ref, sfx)
		}
	}
	return ref
}

func (vs VulnSrc) Get(params db.GetParams) ([]types.Advisory, error) {
	eb := oops.In("suse").Tags("csaf").With("release", params.Release).With("package_name", params.PkgName)
	var bkt bucket.Bucket
	switch vs.dist {
	case SUSEEnterpriseLinuxMicro:
		bkt = bucket.NewSUSELinuxEnterpriseMicro(params.Release)
	case SUSEEnterpriseLinux:
		bkt = bucket.NewSUSELinuxEnterprise(params.Release)
	case OpenSUSE:
		bkt = bucket.NewOpenSUSE(params.Release)
	case OpenSUSETumbleweed:
		bkt = bucket.NewOpenSUSETumbleweed()
	default:
		return nil, eb.Errorf("unknown distribution")
	}

	advisories, err := vs.GetAdvisories(bkt.Name(), params.PkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get advisories")
	}
	return advisories, nil
}

func severityFromThreat(sev string) types.Severity {
	switch sev {
	case "low":
		return types.SeverityLow
	case "moderate":
		return types.SeverityMedium
	case "important":
		return types.SeverityHigh
	case "critical":
		return types.SeverityCritical
	}
	return types.SeverityUnknown
}
