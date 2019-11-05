package oracleoval

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"

	bolt "github.com/etcd-io/bbolt"

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
	dbc db.Operations
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", oracleDir)

	var cves []OracleOVAL
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var cve OracleOVAL
		if err := json.NewDecoder(r).Decode(&cve); err != nil {
			return xerrors.Errorf("failed to decode Oracle Linux OVAL JSON: %w", err)
		}
		cves = append(cves, cve)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in Oracle Linux OVAL walk: %w", err)
	}

	if err = vs.save(cves); err != nil {
		return xerrors.Errorf("error in Oracle Linux OVAL save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(cves []OracleOVAL) error {
	log.Println("Saving Oracle Linux OVAL")

	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, cves)
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}

	return nil

}

func (vs VulnSrc) commit(tx *bolt.Tx, cves []OracleOVAL) error {
	for _, cve := range cves {
		elsaID := strings.TrimLeft(strings.Split(cve.Title, ":")[0], "\n")

		affectedPkgs := walkOracle(cve.Criteria, "", []AffectedPackage{})
		for _, affectedPkg := range affectedPkgs {
			advisory := types.Advisory{
				FixedVersion: affectedPkg.Package.FixedVersion,
			}
			if affectedPkg.Package.Name == "" {
				continue
			}
			platformName := fmt.Sprintf(platformFormat, affectedPkg.OSVer)
			if !utils.StringInSlice(platformName, targetPlatforms) {
				continue
			}
			if err := vs.dbc.PutAdvisory(tx, platformName, affectedPkg.Package.Name, elsaID, advisory); err != nil {
				return xerrors.Errorf("failed to save Oracle Linux OVAL advisory: %w", err)
			}
		}

		var references []string
		for _, ref := range cve.References {
			references = append(references, ref.URI)
		}

		vuln := types.VulnerabilityDetail{
			Description: cve.Description,
			References:  references,
			Title:       strings.TrimLeft(cve.Title, "\n"),
			Severity:    severityFromThreat(cve.Severity),
		}

		if err := vs.dbc.PutVulnerabilityDetail(tx, elsaID, vulnerability.OracleOVAL, vuln); err != nil {
			return xerrors.Errorf("failed to save Oracle Linux OVAL vulnerability: %w", err)
		}

		// for light DB
		if err := vs.dbc.PutSeverity(tx, elsaID, types.SeverityUnknown); err != nil {
			return xerrors.Errorf("failed to save Oracle Linux vulnerability severity: %w", err)
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
		if ss[1] == "0" {
			continue
		}
		pkgs = append(pkgs, AffectedPackage{
			OSVer: osVer,
			Package: Package{
				Name:         ss[0],
				FixedVersion: version.NewVersion(strings.Split(ss[1], " ")[0]).String(),
			},
		})
	}

	if len(cri.Criterias) == 0 {
		return pkgs
	}
	for _, c := range cri.Criterias {
		pkgs = walkOracle(c, osVer, pkgs)
	}
	return pkgs
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
