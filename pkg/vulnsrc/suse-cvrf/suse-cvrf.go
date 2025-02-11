package susecvrf

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
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

type Distribution int

const (
	SUSEEnterpriseLinux Distribution = iota
	SUSEEnterpriseLinuxMicro
	OpenSUSE
	OpenSUSETumbleweed

	platformOpenSUSELeapFormat             = "openSUSE Leap %s"
	platformOpenSUSETumbleweedFormat       = "openSUSE Tumbleweed"
	platformSUSELinuxFormat                = "SUSE Linux Enterprise %s"
	platformSUSELinuxEnterpriseMicroFormat = "SUSE Linux Enterprise Micro %s"
)

var (
	suseDir = filepath.Join("cvrf", "suse")

	source = types.DataSource{
		ID:   vulnerability.SuseCVRF,
		Name: "SUSE CVRF",
		URL:  "https://ftp.suse.com/pub/projects/security/cvrf/",
	}
)

type VulnSrc struct {
	dist   Distribution
	dbc    db.Operation
	logger *log.Logger
}

func NewVulnSrc(dist Distribution) VulnSrc {
	return VulnSrc{
		dist:   dist,
		dbc:    db.Config{},
		logger: log.WithPrefix("suse-cvrf"),
	}
}

func (vs VulnSrc) Name() types.SourceID {
	if vs.dist == OpenSUSE {
		return "opensuse-cvrf"
	}
	if vs.dist == OpenSUSETumbleweed {
		return "opensuse-tumbleweed-cvrf"
	}
	return source.ID
}

func (vs VulnSrc) Update(dir string) error {
	vs.logger.Info("Saving SUSE CVRF")
	rootDir := filepath.Join(dir, "vuln-list", suseDir)
	eb := oops.In("suse").Tags("cvrf").With("root_dir", rootDir)

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
		var cvrf SuseCvrf
		if err := json.NewDecoder(r).Decode(&cvrf); err != nil {
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

func (vs VulnSrc) save(cvrfs []SuseCvrf) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, cvrfs)
	})
	if err != nil {
		return oops.Wrapf(err, "batch update error")
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, cvrfs []SuseCvrf) error {
	for _, cvrf := range cvrfs {
		affectedPkgs := vs.getAffectedPackages(cvrf.ProductTree.Relationships)
		if len(affectedPkgs) == 0 {
			continue
		}

		for _, affectedPkg := range affectedPkgs {
			advisory := types.Advisory{
				FixedVersion: affectedPkg.Package.FixedVersion,
			}

			if err := vs.dbc.PutDataSource(tx, affectedPkg.OSVer, source); err != nil {
				return oops.Wrapf(err, "failed to put data source")
			}

			if err := vs.dbc.PutAdvisoryDetail(tx, cvrf.Tracking.ID, affectedPkg.Package.Name,
				[]string{affectedPkg.OSVer}, advisory); err != nil {
				return oops.Wrapf(err, "unable to save CVRF")
			}
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

		vuln := types.VulnerabilityDetail{
			References:  references,
			Title:       cvrf.Title,
			Description: getDetail(cvrf.Notes),
			Severity:    severity,
		}

		if err := vs.dbc.PutVulnerabilityDetail(tx, cvrf.Tracking.ID, source.ID, vuln); err != nil {
			return oops.With("tracking_id", cvrf.Tracking.ID).Wrapf(err, "failed to save SUSE CVRF vulnerability")
		}

		// for optimization
		if err := vs.dbc.PutVulnerabilityID(tx, cvrf.Tracking.ID); err != nil {
			return oops.With("tracking_id", cvrf.Tracking.ID).Wrapf(err, "failed to save the vulnerability ID")
		}
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

		pkg := getPackage(relationship.ProductReference)
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

func (vs VulnSrc) getOSVersion(platformName string) string {
	if strings.Contains(platformName, "SUSE Manager") {
		// SUSE Linux Enterprise Module for SUSE Manager Server 4.0
		return ""
	}
	if strings.HasPrefix(platformName, "openSUSE Tumbleweed") {
		// Tumbleweed has no version, it is a rolling release
		return platformOpenSUSETumbleweedFormat
	}
	if strings.HasPrefix(platformName, "openSUSE Leap") {
		// openSUSE Leap 15.0
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
		return fmt.Sprintf(platformOpenSUSELeapFormat, ss[2])
	}
	if strings.HasPrefix(platformName, "SUSE Linux Enterprise Micro") {
		// SUSE Linux Enterprise Micro 5.3
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
		return fmt.Sprintf(platformSUSELinuxEnterpriseMicroFormat, ss[4])
	}
	if strings.Contains(platformName, "SUSE Linux Enterprise") {
		// e.g. SUSE Linux Enterprise Storage 7
		if strings.HasPrefix(platformName, "SUSE Linux Enterprise Storage") {
			return ""
		}

		ss := strings.Fields(strings.ReplaceAll(platformName, "-", " "))
		versions := make([]string, 0, 2)
		for i := len(ss) - 1; i > 0; i-- {
			v, err := strconv.Atoi(strings.TrimPrefix(ss[i], "SP"))
			if err != nil {
				continue
			}
			versions = append(versions, fmt.Sprintf("%d", v))
			if len(versions) == 2 {
				break
			}
		}
		switch len(versions) {
		case 0:
			vs.logger.Warn("Failed to detect version", log.String("platform", platformName))
			return ""
		case 1:
			return fmt.Sprintf(platformSUSELinuxFormat, versions[0])
		case 2:
			return fmt.Sprintf(platformSUSELinuxFormat, fmt.Sprintf("%s.%s", versions[1], versions[0]))
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
	name, version := splitPkgName(packVer)
	return &Package{
		Name:         name,
		FixedVersion: version,
	}
}

// reference: https://github.com/aquasecurity/trivy-db/blob/5c844be3ba6b9ef13df640857a10f8737e360feb/pkg/vulnsrc/redhat/redhat.go#L196-L217
func splitPkgName(pkgName string) (string, string) {
	var version string

	// Trim release
	index := strings.LastIndex(pkgName, "-")
	if index == -1 {
		return "", ""
	}
	version = pkgName[index:]
	pkgName = pkgName[:index]

	// Trim version
	index = strings.LastIndex(pkgName, "-")
	if index == -1 {
		return "", ""
	}
	version = pkgName[index+1:] + version
	pkgName = pkgName[:index]

	return pkgName, version
}

func (vs VulnSrc) Get(version string, pkgName string) ([]types.Advisory, error) {
	eb := oops.In("suse").Tags("cvrf").With("version", version).With("package_name", pkgName)
	var bucket string
	switch vs.dist {
	case SUSEEnterpriseLinuxMicro:
		bucket = fmt.Sprintf(platformSUSELinuxEnterpriseMicroFormat, version)
	case SUSEEnterpriseLinux:
		bucket = fmt.Sprintf(platformSUSELinuxFormat, version)
	case OpenSUSE:
		bucket = fmt.Sprintf(platformOpenSUSELeapFormat, version)
	case OpenSUSETumbleweed:
		bucket = platformOpenSUSETumbleweedFormat
	default:
		return nil, eb.Errorf("unknown distribution")
	}

	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
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
