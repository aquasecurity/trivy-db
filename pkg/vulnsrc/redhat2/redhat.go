package redhat2

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/types"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/utils"
)

const (
	platformFormat = "Red Hat Enterprise Linux OvalV2 %s"
)

var (
	redhatDir       = filepath.Join("oval", "redhat2")
	targetPlatforms = []string{"Red Hat Enterprise Linux OvalV2 5", "Red Hat Enterprise Linux OvalV2 6", "Red Hat Enterprise Linux OvalV2 7", "Red Hat Enterprise Linux OvalV2 8"}
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

	var ovals []RedhatOVAL
	err := utils.FileWalk(rootDir, func(r io.Reader, _ string) error {
		content, err := ioutil.ReadAll(r)
		if err != nil {
			return err
		}
		oval := RedhatOVAL{}
		if err = json.Unmarshal(content, &oval); err != nil {
			return xerrors.Errorf("failed to decode RedHat JSON: %w", err)
		}
		ovals = append(ovals, oval)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in Red Hat walk: %w", err)
	}

	if err = vs.save(ovals); err != nil {
		return xerrors.Errorf("error in Red Hat save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(ovals []RedhatOVAL) error {
	log.Println("Saving RedHat DB")
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, ovals)
	})
	if err != nil {
		return xerrors.Errorf("failed batch update: %w", err)
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, ovals []RedhatOVAL) error {
	for _, oval := range ovals {
		// for _, pkgState := range oval.PackageState {
		// 	pkgName := pkgState.PackageName
		// 	if pkgName == "" {
		// 		continue
		// 	}
		// 	// e.g. Red Hat Enterprise Linux 7
		// 	platformName := pkgState.ProductName
		// 	if !utils.StringInSlice(platformName, targetPlatforms) {
		// 		continue
		// 	}
		// 	if !utils.StringInSlice(pkgState.FixState, targetStatus) {
		// 		continue
		// 	}

		// 	advisory := types.Advisory{
		// 		// this means all versions
		// 		FixedVersion: "",
		// 	}
		// 	if err := vs.dbc.PutAdvisoryDetail(tx, cve.Name, platformName, pkgName, advisory); err != nil {
		// 		return xerrors.Errorf("failed to save Red Hat advisory: %w", err)
		// 	}
		// }

		// cvssScore, _ := strconv.ParseFloat(cve.Cvss.CvssBaseScore, 64)
		// cvss3Score, _ := strconv.ParseFloat(cve.Cvss3.Cvss3BaseScore, 64)

		// title := strings.TrimPrefix(strings.TrimSpace(cve.Bugzilla.Description), cve.Name)

		// vuln := types.VulnerabilityDetail{
		// 	CvssScore:    cvssScore,
		// 	CvssVector:   cve.Cvss.CvssScoringVector,
		// 	CvssScoreV3:  cvss3Score,
		// 	CvssVectorV3: cve.Cvss3.Cvss3ScoringVector,
		// 	Severity:     severityFromThreat(cve.ThreatSeverity),
		// 	References:   cve.References,
		// 	Title:        strings.TrimSpace(title),
		// 	Description:  strings.TrimSpace(strings.Join(cve.Details, "")),
		// }
		// if err := vs.dbc.PutVulnerabilityDetail(tx, cve.Name, vulnerability.RedHat, vuln); err != nil {
		// 	return xerrors.Errorf("failed to save Red Hat vulnerability: %w", err)
		// }

		// // for light DB
		// if err := vs.dbc.PutSeverity(tx, cve.Name, types.SeverityUnknown); err != nil {
		// 	return xerrors.Errorf("failed to save Red Hat vulnerability severity: %w", err)
		// }
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
