package redhat

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/types"

	bolt "github.com/etcd-io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	redhatDir      = "redhat"
	platformFormat = "Red Hat Enterprise Linux %s"
)

var (
	targetPlatforms = []string{"Red Hat Enterprise Linux 5", "Red Hat Enterprise Linux 6", "Red Hat Enterprise Linux 7"}
	targetStatus    = []string{"Affected", "Fix deferred", "Will not fix"}
)

type VulnSrc struct {
	dbc db.Operations
}

func NewVulnSrc() types.VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, redhatDir)

	var cves []RedhatCVE
	err := utils.FileWalk(rootDir, func(r io.Reader, _ string) error {
		content, err := ioutil.ReadAll(r)
		if err != nil {
			return err
		}
		cve := RedhatCVE{}
		if err = json.Unmarshal(content, &cve); err != nil {
			return xerrors.Errorf("failed to decode RedHat JSON: %w", err)
		}
		switch cve.TempAffectedRelease.(type) {
		case []interface{}:
			var ar RedhatCVEAffectedReleaseArray
			if err = json.Unmarshal(content, &ar); err != nil {
				return xerrors.Errorf("unknown affected_release type: %w", err)
			}
			cve.AffectedRelease = ar.AffectedRelease
		case map[string]interface{}:
			var ar RedhatCVEAffectedReleaseObject
			if err = json.Unmarshal(content, &ar); err != nil {
				return xerrors.Errorf("unknown affected_release type: %w", err)
			}
			cve.AffectedRelease = []RedhatAffectedRelease{ar.AffectedRelease}
		case nil:
		default:
			return xerrors.New("unknown affected_release type")
		}

		switch cve.TempPackageState.(type) {
		case []interface{}:
			var ps RedhatCVEPackageStateArray
			if err = json.Unmarshal(content, &ps); err != nil {
				return xerrors.Errorf("unknown package_state type: %w", err)
			}
			cve.PackageState = ps.PackageState
		case map[string]interface{}:
			var ps RedhatCVEPackageStateObject
			if err = json.Unmarshal(content, &ps); err != nil {
				return xerrors.Errorf("unknown package_state type: %w", err)
			}
			cve.PackageState = []RedhatPackageState{ps.PackageState}
		case nil:
		default:
			return xerrors.New("unknown package_state type")
		}
		cves = append(cves, cve)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in RedHat walk: %w", err)
	}

	if err = vs.save(cves); err != nil {
		return xerrors.Errorf("error in RedHat save: %w", err)
	}

	return nil
}

// platformName: pkgStatus
type platform map[string]pkg

// pkgName: advisoryStatus
type pkg map[string]advisory

// cveID: version
type advisory map[string]interface{}

func (vs VulnSrc) save(cves []RedhatCVE) error {
	log.Println("Saving RedHat DB")
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		for _, cve := range cves {
			for _, affected := range cve.AffectedRelease {
				if affected.Package == "" {
					continue
				}
				// e.g. Red Hat Enterprise Linux 7
				platformName := affected.ProductName
				if !utils.StringInSlice(affected.ProductName, targetPlatforms) {
					continue
				}

				pkgName, version := splitPkgName(affected.Package)
				advisory := types.Advisory{
					VulnerabilityID: cve.Name,
					FixedVersion:    version,
				}
				if err := vs.dbc.PutAdvisory(tx, platformName, pkgName, cve.Name, advisory); err != nil {
					return xerrors.Errorf("failed to save Red Hat advisory: %w", err)
				}

			}

			for _, pkgState := range cve.PackageState {
				pkgName := pkgState.PackageName
				if pkgName == "" {
					continue
				}
				// e.g. Red Hat Enterprise Linux 7
				platformName := pkgState.ProductName
				if !utils.StringInSlice(platformName, targetPlatforms) {
					continue
				}
				if !utils.StringInSlice(pkgState.FixState, targetStatus) {
					continue
				}

				advisory := types.Advisory{
					// this means all versions
					FixedVersion:    "",
					VulnerabilityID: cve.Name,
				}
				if err := vs.dbc.PutAdvisory(tx, platformName, pkgName, cve.Name, advisory); err != nil {
					return xerrors.Errorf("failed to save Red Hat advisory: %w", err)
				}

			}

			cvssScore, _ := strconv.ParseFloat(cve.Cvss.CvssBaseScore, 64)
			cvss3Score, _ := strconv.ParseFloat(cve.Cvss3.Cvss3BaseScore, 64)

			title := strings.TrimPrefix(strings.TrimSpace(cve.Bugzilla.Description), cve.Name)

			vuln := types.VulnerabilityDetail{
				CvssScore:   cvssScore,
				CvssScoreV3: cvss3Score,
				Severity:    severityFromThreat(cve.ThreatSeverity),
				References:  cve.References,
				Title:       strings.TrimSpace(title),
				Description: strings.TrimSpace(strings.Join(cve.Details, "")),
			}
			if err := vs.dbc.PutVulnerabilityDetail(tx, cve.Name, vulnerability.RedHat, vuln); err != nil {
				return xerrors.Errorf("failed to save Red Hat vulnerability: %w", err)
			}

			// for light DB
			if err := vs.dbc.PutSeverity(tx, cve.Name, types.SeverityUnknown); err != nil {
				return xerrors.Errorf("failed to save alpine vulnerability severity: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

func (vs VulnSrc) Get(majorVersion string, pkgName string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, majorVersion)
	advisories, err := vs.dbc.ForEachAdvisory(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("error in Red Hat foreach: %w", err)
	}
	if len(advisories) == 0 {
		return nil, nil
	}

	var results []types.Advisory
	for _, v := range advisories {
		var advisory types.Advisory
		if err = json.Unmarshal(v, &advisory); err != nil {
			return nil, xerrors.Errorf("failed to unmarshal Red Hat JSON: %w", err)
		}
		results = append(results, advisory)
	}
	return results, nil
}

// ref. https://github.com/rpm-software-management/yum/blob/043e869b08126c1b24e392f809c9f6871344c60d/rpmUtils/miscutils.py#L301
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

func severityFromThreat(sev string) types.Severity {
	switch strings.Title(sev) {
	case "Low":
		return types.SeverityLow
	case "Moderate":
		return types.SeverityMedium
	case "Important":
		return types.SeverityHigh
	case "Critical":
		return types.SeverityCritical
	}
	return types.SeverityUnknown
}
