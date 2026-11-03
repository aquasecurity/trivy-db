package susecsaf

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/gocsaf/csaf/v3/csaf"
	rpmversion "github.com/knqyf263/go-rpm-version"
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
)

const (
	vulnListDir = "vuln-list-suse"
	csafDir     = "csaf/suse"
)

var (
	source = types.DataSource{
		ID:   vulnerability.SuseCSAF,
		Name: "SUSE CSAF",
		URL:  "https://ftp.suse.com/pub/projects/security/csaf/",
	}
)

type PutInput struct {
	VulnID string

	// Advisory is the CSAF document the other fields were derived from.
	Advisory Advisory

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

		var adv Advisory
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
func (vs VulnSrc) buildInput(adv Advisory) (PutInput, error) {
	doc := adv.Document
	vulnID := doc.Tracking.ID
	if vulnID == "" {
		return PutInput{}, errors.New("missing tracking id")
	}

	references := make([]string, 0, len(doc.References))
	for _, ref := range doc.References {
		if ref.URL == "" {
			continue
		}
		references = append(references, ref.URL)
	}

	return PutInput{
		VulnID:   vulnID,
		Advisory: adv,
		Vuln: types.VulnerabilityDetail{
			References:  references,
			Title:       doc.Title,
			Description: description(doc.Notes),
			Severity:    severityFromAdvisory(doc, adv.Vulnerabilities),
		},
		AffectedPkgs: vs.getAffectedPackages(adv.ProductTree.Relationships, adv.Vulnerabilities),
	}, nil
}

// description returns the text of the "description" note, which SUSE uses for the advisory body.
func description(notes []Note) string {
	for _, n := range notes {
		if n.Category == string(csaf.CSAFNoteCategoryDescription) {
			return n.Text
		}
	}
	return ""
}

// severityFromAdvisory prefers per-CVE impact threats and falls back to document.aggregate_severity.
func severityFromAdvisory(doc Document, vulns []Vulnerability) types.Severity {
	if sev := highestImpact(vulns); sev != types.SeverityUnknown {
		return sev
	}
	return severityFromThreat(doc.AggregateSeverity.Text)
}

// highestImpact returns the most severe impact rating across all vulnerabilities in the advisory.
func highestImpact(vulns []Vulnerability) types.Severity {
	severity := types.SeverityUnknown
	for _, vuln := range vulns {
		for _, threat := range vuln.Threats {
			if threat.Category != string(csaf.CSAFThreatCategoryImpact) {
				continue
			}
			if sev := severityFromThreat(threat.Details); severity < sev {
				severity = sev
			}
		}
	}
	return severity
}

// allowedProductIDs collects product IDs marked as fixed or recommended across all vulnerabilities to filter remediated packages.
func allowedProductIDs(vulns []Vulnerability) map[string]struct{} {
	allowed := make(map[string]struct{})
	for _, vuln := range vulns {
		for _, pid := range slices.Concat(vuln.ProductStatus.Fixed, vuln.ProductStatus.Recommended) {
			allowed[pid] = struct{}{}
		}
	}
	return allowed
}

// commit writes a single advisory. savedDataSources is shared across the whole walk so
// that each OS version's data source is written only once.
func (vs VulnSrc) commit(tx *bolt.Tx, adv Advisory, savedDataSources map[string]struct{}) error {
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

		if err := vs.PutDataSource(tx, affectedPkg.OSVer, source); err != nil {
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

	if err := vs.PutVulnerabilityDetail(tx, input.VulnID, source.ID, input.Vuln); err != nil {
		return oops.With("tracking_id", input.VulnID).Wrapf(err, "failed to save SUSE CSAF vulnerability")
	}

	if err := vs.PutVulnerabilityID(tx, input.VulnID); err != nil {
		return oops.With("tracking_id", input.VulnID).Wrapf(err, "failed to save the vulnerability ID")
	}
	return nil
}

func (vs VulnSrc) getAffectedPackages(relationships []Relationship, vulns []Vulnerability) []AffectedPackage {
	allowed := allowedProductIDs(vulns)
	seen := make(map[AffectedPackage]struct{})
	var pkgs []AffectedPackage

	for _, relationship := range relationships {
		platform := relationship.RelatesToProductReference
		productRef := relationship.ProductReference
		// When vulnerabilities are present, keep only packages remediated by this advisory.
		// When an advisory omits vulnerabilities altogether (non-CVE security updates e.g. SUSE-SU-2022:1714-1),
		// all packages in product_tree represent updates delivered by the advisory.
		if len(vulns) > 0 {
			if _, ok := allowed[relationship.FullProductName.ProductID]; !ok {
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

		affectedPkg := AffectedPackage{
			OSVer:   osVer,
			Package: *pkg,
		}
		if _, ok := seen[affectedPkg]; ok {
			continue
		}
		seen[affectedPkg] = struct{}{}

		pkgs = append(pkgs, affectedPkg)
	}

	return pkgs
}

// TODO: getOSVersion logic is duplicated from suse-cvrf so that suse-csaf remains
// self-contained when suse-cvrf is removed in the future.
//
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
		Name: name,
		// CSAF versions carry an explicit zero epoch, which other RPM sources (and suse-cvrf) omit:
		// "0:2.9.4-36.1" -> "2.9.4-36.1". A non-zero epoch is kept.
		FixedVersion: rpmversion.NewVersion(ver).String(),
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

var archSuffixes = []string{
	".aarch64_ilp32", ".x86_64", ".aarch64", ".ppc64le", ".s390x", ".i586", ".ia64",
	".riscv64", ".armv7hl", ".armv7l", ".ppc64", ".arm64", ".noarch", ".i686", ".ppc", ".s390",
}

func stripArchSuffix(ref string) string {
	for _, sfx := range archSuffixes {
		if before, ok := strings.CutSuffix(ref, sfx); ok {
			return before
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
	switch strings.ToLower(strings.TrimSpace(sev)) {
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
