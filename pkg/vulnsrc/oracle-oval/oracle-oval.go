package oracleoval

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"

	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	version "github.com/knqyf263/go-rpm-version"
	"golang.org/x/xerrors"
)

var (
	// cat /etc/os-release ORACLE_BUGZILLA_PRODUCT="Oracle Linux 8"
	platformFormat  = "Oracle Linux %s"
	targetPlatforms = []string{"Oracle Linux 5", "Oracle Linux 6", "Oracle Linux 7", "Oracle Linux 8"}
	oracleDir       = filepath.Join("oval", "oracle")
)

type VulnSrc struct {
	dbc db.Operation
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Name() string {
	return vulnerability.OracleOVAL
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", oracleDir)

	var ovals []OracleOVAL
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var oval OracleOVAL
		if err := json.NewDecoder(r).Decode(&oval); err != nil {
			return xerrors.Errorf("failed to decode Oracle Linux OVAL JSON: %w", err)
		}
		ovals = append(ovals, oval)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in Oracle Linux OVAL walk: %w", err)
	}

	if err = vs.save(ovals); err != nil {
		return xerrors.Errorf("error in Oracle Linux OVAL save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(ovals []OracleOVAL) error {
	log.Println("Saving Oracle Linux OVAL")

	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, ovals)
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}

	return nil

}

func (vs VulnSrc) commit(tx *bolt.Tx, ovals []OracleOVAL) error {
	for _, oval := range ovals {
		elsaID := strings.Split(oval.Title, ":")[0]

		var vulnIDs []string
		for _, cve := range oval.Cves {
			vulnIDs = append(vulnIDs, cve.ID)
		}
		if len(vulnIDs) == 0 {
			vulnIDs = append(vulnIDs, elsaID)
		}

		affectedPkgs := walkOracle(oval.Criteria, "", []AffectedPackage{})
		for _, affectedPkg := range affectedPkgs {
			if affectedPkg.Package.Name == "" {
				continue
			}

			platformName := fmt.Sprintf(platformFormat, affectedPkg.OSVer)
			if !utils.StringInSlice(platformName, targetPlatforms) {
				continue
			}

			advisory := types.Advisory{
				FixedVersion: affectedPkg.Package.FixedVersion,
			}

			for _, vulnID := range vulnIDs {
				if err := vs.dbc.PutAdvisoryDetail(tx, vulnID, platformName, affectedPkg.Package.Name, advisory); err != nil {
					return xerrors.Errorf("failed to save Oracle Linux OVAL: %w", err)
				}
			}
		}

		var references []string
		for _, ref := range oval.References {
			references = append(references, ref.URI)
		}

		for _, vulnID := range vulnIDs {
			vuln := types.VulnerabilityDetail{
				Description: oval.Description,
				References:  referencesFromContains(references, []string{elsaID, vulnID}),
				Title:       oval.Title,
				Severity:    severityFromThreat(oval.Severity),
			}

			if err := vs.dbc.PutVulnerabilityDetail(tx, vulnID, vulnerability.OracleOVAL, vuln); err != nil {
				return xerrors.Errorf("failed to save Oracle Linux OVAL vulnerability: %w", err)
			}

			// for light DB
			if err := vs.dbc.PutSeverity(tx, vulnID, types.SeverityUnknown); err != nil {
				return xerrors.Errorf("failed to save Oracle Linux vulnerability severity: %w", err)
			}
		}
	}
	return nil

}

func (vs VulnSrc) Get(release string, pkgName string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, release)
	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get Oracle Linux advisories: %w", err)
	}
	return advisories, nil
}

func walkOracle(cri Criteria, osVer string, pkgs []AffectedPackage) []AffectedPackage {
	for _, c := range cri.Criterions {
		if strings.HasPrefix(c.Comment, "Oracle Linux ") &&
			strings.HasSuffix(c.Comment, " is installed") {
			osVer = strings.TrimSuffix(strings.TrimPrefix(c.Comment, "Oracle Linux "), " is installed")
		}
		ss := strings.Split(c.Comment, " is earlier than ")
		if len(ss) != 2 {
			continue
		}

		pkgs = append(pkgs, AffectedPackage{
			OSVer: osVer,
			Package: Package{
				Name:         ss[0],
				FixedVersion: version.NewVersion(ss[1]).String(),
			},
		})
	}

	for _, c := range cri.Criterias {
		pkgs = walkOracle(c, osVer, pkgs)
	}
	return pkgs
}

func referencesFromContains(sources []string, matches []string) []string {
	references := []string{}
	for _, s := range sources {
		for _, m := range matches {
			if strings.Contains(s, m) {
				references = append(references, s)
			}
		}
	}
	return utils.Uniq(references)
}

func severityFromThreat(sev string) types.Severity {
	switch sev {
	case "LOW":
		return types.SeverityLow
	case "MODERATE":
		return types.SeverityMedium
	case "IMPORTANT":
		return types.SeverityHigh
	case "CRITICAL":
		return types.SeverityCritical
	}
	return types.SeverityUnknown
}
