package redhat

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strconv"
	"strings"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	vulnListDir = "vuln-list-redhat"
	apiDir      = "api"

	resourceURL = "https://access.redhat.com/security/cve/%s"
)

type VulnSrc struct {
	dbc db.Operation
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Name() types.SourceID {
	return vulnerability.RedHat
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, vulnListDir, apiDir)

	var cves []RedhatCVE
	err := utils.FileWalk(rootDir, func(r io.Reader, _ string) error {
		content, err := io.ReadAll(r)
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
	log.Println("Saving Red Hat DB")
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
		if err := vs.putVulnerabilityDetail(tx, cve); err != nil {
			return err
		}
	}

	return nil
}

func (vs VulnSrc) putVulnerabilityDetail(tx *bolt.Tx, cve RedhatCVE) error {
	cvssScore, _ := strconv.ParseFloat(cve.Cvss.CvssBaseScore, 64)
	cvss3Score, _ := strconv.ParseFloat(cve.Cvss3.Cvss3BaseScore, 64)
	title := strings.TrimPrefix(strings.TrimSpace(cve.Bugzilla.Description), cve.Name)
	references := append(cve.References, fmt.Sprintf(resourceURL, cve.Name))

	vuln := types.VulnerabilityDetail{
		CvssScore:    cvssScore,
		CvssVector:   cve.Cvss.CvssScoringVector,
		CvssScoreV3:  cvss3Score,
		CvssVectorV3: cve.Cvss3.Cvss3ScoringVector,
		Severity:     severityFromThreat(cve.ThreatSeverity),
		References:   references,
		Title:        strings.TrimSpace(title),
		Description:  strings.TrimSpace(strings.Join(cve.Details, "")),
	}
	if err := vs.dbc.PutVulnerabilityDetail(tx, cve.Name, vulnerability.RedHat, vuln); err != nil {
		return xerrors.Errorf("failed to save Red Hat vulnerability: %w", err)
	}

	// for optimization
	if err := vs.dbc.PutVulnerabilityID(tx, cve.Name); err != nil {
		return xerrors.Errorf("failed to save the vulnerability ID: %w", err)
	}
	return nil
}

func severityFromThreat(sev string) types.Severity {
	severity := cases.Title(language.English).String(sev)
	switch severity {
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
