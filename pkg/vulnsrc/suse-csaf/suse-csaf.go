package susecsaf

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"

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
)

type PutInput struct {
	Cvrf         SuseCvrf
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

	var cvrfs []SuseCvrf
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		cvrf, err := decodeAdvisory(r)
		if err != nil {
			return eb.With("file_path", path).Wrapf(err, "json decode error")
		}
		cvrfs = append(cvrfs, cvrf)
		return nil
	})
	if err != nil {
		return eb.Wrapf(err, "walk error")
	}

	if err = vs.save(cvrfs); err != nil {
		return eb.Wrapf(err, "save error")
	}

	return nil
}

func decodeAdvisory(r io.Reader) (SuseCvrf, error) {
	var csaf SuseCSAF
	if err := json.NewDecoder(r).Decode(&csaf); err != nil {
		return SuseCvrf{}, err
	}
	if csaf.Document.Tracking.ID == "" {
		return SuseCvrf{}, fmt.Errorf("missing tracking id")
	}
	return toCvrf(csaf), nil
}

func toCvrf(csaf SuseCSAF) SuseCvrf {
	cvrf := SuseCvrf{
		Title: csaf.Document.Title,
		Tracking: DocumentTracking{
			ID: csaf.Document.Tracking.ID,
		},
		References: make([]Reference, 0, len(csaf.Document.References)),
		Notes:      make([]DocumentNote, 0, len(csaf.Document.Notes)),
		ProductTree: ProductTree{
			Relationships: make([]Relationship, 0, len(csaf.ProductTree.Relationships)),
		},
		Vulnerabilities: make([]Vulnerability, 0, len(csaf.Vulnerabilities)),
	}

	for _, n := range csaf.Document.Notes {
		noteType := ""
		noteTitle := n.Title
		switch n.Category {
		case "summary":
			noteType = "Summary"
			if noteTitle == "" {
				noteTitle = "Topic"
			}
		case "description":
			noteType = "General"
			noteTitle = "Details"
		default:
			continue
		}
		cvrf.Notes = append(cvrf.Notes, DocumentNote{
			Text:  n.Text,
			Title: noteTitle,
			Type:  noteType,
		})
	}

	for _, ref := range csaf.Document.References {
		cvrf.References = append(cvrf.References, Reference{URL: ref.URL})
	}
	for _, rel := range csaf.ProductTree.Relationships {
		cvrf.ProductTree.Relationships = append(cvrf.ProductTree.Relationships, Relationship{
			ProductReference:          rel.ProductReference,
			RelatesToProductReference: rel.RelatesToProductReference,
		})
	}
	for _, v := range csaf.Vulnerabilities {
		vuln := Vulnerability{}
		for _, t := range v.Threats {
			if t.Category != "impact" {
				continue
			}
			vuln.Threats = append(vuln.Threats, Threat{
				Type:     "Impact",
				Severity: t.Details,
			})
		}
		cvrf.Vulnerabilities = append(cvrf.Vulnerabilities, vuln)
	}

	return cvrf
}

func (vs VulnSrc) save(cvrfs []SuseCvrf) error {
	err := vs.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, cvrfs)
	})
	if err != nil {
		return oops.Wrapf(err, "batch update error")
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, cvrfs []SuseCvrf) error {
	var savedDataSources = make(map[string]struct{})
	for _, cvrf := range cvrfs {
		affectedPkgs := vs.getAffectedPackages(cvrf.ProductTree.Relationships)
		if len(affectedPkgs) == 0 {
			continue
		}

		for _, affectedPkg := range affectedPkgs {
			if _, ok := savedDataSources[affectedPkg.OSVer]; ok {
				continue
			}

			if err := vs.PutDataSource(tx, affectedPkg.OSVer, source); err != nil {
				return oops.Wrapf(err, "failed to put data source")
			}
			savedDataSources[affectedPkg.OSVer] = struct{}{}
		}

		var references []string
		for _, ref := range cvrf.References {
			references = append(references, ref.URL)
		}

		severity := types.SeverityUnknown
		for _, cvuln := range cvrf.Vulnerabilities {
			for _, threat := range cvuln.Threats {
				sev := severityFromThreat(threat.Severity)
				if severity < sev {
					severity = sev
				}
			}
		}

		input := PutInput{
			Cvrf: cvrf,
			Vuln: types.VulnerabilityDetail{
				References:  references,
				Title:       cvrf.Title,
				Description: getDetail(cvrf.Notes),
				Severity:    severity,
			},
			AffectedPkgs: affectedPkgs,
		}

		if err := vs.Put(tx, input); err != nil {
			return oops.Wrapf(err, "Put error")
		}
	}
	return nil
}

func (vs *Suse) Put(tx *bolt.Tx, input PutInput) error {
	for _, affectedPkg := range input.AffectedPkgs {
		advisory := types.Advisory{
			FixedVersion: affectedPkg.Package.FixedVersion,
		}

		if err := vs.PutAdvisoryDetail(tx, input.Cvrf.Tracking.ID, affectedPkg.Package.Name,
			[]string{affectedPkg.OSVer}, advisory); err != nil {
			return oops.Wrapf(err, "unable to save CSAF advisory")
		}
	}

	if err := vs.PutVulnerabilityDetail(tx, input.Cvrf.Tracking.ID, source.ID, input.Vuln); err != nil {
		return oops.With("tracking_id", input.Cvrf.Tracking.ID).Wrapf(err, "failed to save SUSE CSAF vulnerability")
	}

	if err := vs.PutVulnerabilityID(tx, input.Cvrf.Tracking.ID); err != nil {
		return oops.With("tracking_id", input.Cvrf.Tracking.ID).Wrapf(err, "failed to save the vulnerability ID")
	}
	return nil
}

func (vs VulnSrc) getAffectedPackages(relationships []Relationship) []AffectedPackage {
	var pkgs []AffectedPackage
	for _, relationship := range relationships {
		osVer := vs.getOSVersion(relationship.RelatesToProductReference)
		if osVer == "" {
			continue
		}

		pkg := getPackage(stripArchSuffix(relationship.ProductReference))
		if pkg == nil {
			vs.logger.Warn("Invalid package name", log.String("reference", relationship.ProductReference))
			continue
		}

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

func getDetail(notes []DocumentNote) string {
	for _, n := range notes {
		if n.Type == "General" && n.Title == "Details" {
			return n.Text
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
		".aarch64", ".x86_64", ".ppc64le", ".s390x", ".i586",
		".riscv64", ".armv7hl", ".armv7l", ".ppc64", ".arm64",
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
