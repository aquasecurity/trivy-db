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

	bolt "go.etcd.io/bbolt"
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
	targetPlatforms = []string{"Red Hat Enterprise Linux 5", "Red Hat Enterprise Linux 6", "Red Hat Enterprise Linux 7", "Red Hat Enterprise Linux 8"}
	targetStatus    = []string{"Affected", "Fix deferred", "Will not fix"}
)

type VulnSrc struct {
	dbc db.Operation
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", redhatDir)

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
		return xerrors.Errorf("error in Red Hat walk: %w", err)
	}

	if err = vs.save(cves); err != nil {
		return xerrors.Errorf("error in Red Hat save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(cves []RedhatCVE) error {
	log.Println("Saving RedHat DB")
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, cves)
	})
	if err != nil {
		return xerrors.Errorf("failed batch update: %w", err)
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, cves []RedhatCVE) error {
	for _, cve := range cves {
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
				FixedVersion: "",
			}
			if err := vs.dbc.PutAdvisory(tx, platformName, pkgName, cve.Name, advisory); err != nil {
				return xerrors.Errorf("failed to save Red Hat advisory: %w", err)
			}
		}

		cvssScore, _ := strconv.ParseFloat(cve.Cvss.CvssBaseScore, 64)
		cvss3Score, _ := strconv.ParseFloat(cve.Cvss3.Cvss3BaseScore, 64)

		title := strings.TrimPrefix(strings.TrimSpace(cve.Bugzilla.Description), cve.Name)

		vuln := types.VulnerabilityDetail{
			CvssScore:    cvssScore,
			CvssVector:   cve.Cvss.CvssScoringVector,
			CvssScoreV3:  cvss3Score,
			CvssVectorV3: cve.Cvss3.Cvss3ScoringVector,
			Severity:     severityFromThreat(cve.ThreatSeverity),
			References:   cve.References,
			Title:        strings.TrimSpace(title),
			Description:  strings.TrimSpace(strings.Join(cve.Details, "")),
		}
		if err := vs.dbc.PutVulnerabilityDetail(tx, cve.Name, vulnerability.RedHat, vuln); err != nil {
			return xerrors.Errorf("failed to save Red Hat vulnerability: %w", err)
		}

		// for light DB
		if err := vs.dbc.PutSeverity(tx, cve.Name, types.SeverityUnknown); err != nil {
			return xerrors.Errorf("failed to save Red Hat vulnerability severity: %w", err)
		}
	}

	return nil
}

func (vs VulnSrc) Get(majorVersion string, pkgName string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, majorVersion)
	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get Red Hat advisories: %w", err)
	}
	return advisories, nil
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
