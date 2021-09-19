package alma

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	almaDir = "alma"
)

var (
	platformFormat = "alma %s"
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
	return vulnerability.Alma
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", almaDir)
	errata := map[string][]erratum{}
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var erratum erratum
		if err := json.NewDecoder(r).Decode(&erratum); err != nil {
			return xerrors.Errorf("failed to decode Alma erratum: %w", err)
		}

		dirs := strings.Split(path, string(filepath.Separator))
		if len(dirs) < 3 {
			log.Printf("invalid path: %s\n", path)
			return nil
		}

		version := dirs[len(dirs)-3]
		errata[version] = append(errata[version], erratum)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in Alma walk: %w", err)
	}

	if err := vs.save(errata); err != nil {
		return xerrors.Errorf("error in Alma save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(errataVer map[string][]erratum) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		for version, errata := range errataVer {
			if err := vs.commit(tx, version, errata); err != nil {
				return xerrors.Errorf("error in save Alma %s: %w", version, err)
			}
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in db batch update: %w", err)
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, version string, errata []erratum) error {
	platformName := fmt.Sprintf(platformFormat, version)
	for _, erratum := range errata {
		references := []string{}
		for _, ref := range erratum.References {
			if ref.Type != "cve" {
				references = append(references, ref.Href)
			}
		}

		for _, ref := range erratum.References {
			if ref.Type != "cve" {
				continue
			}

			cveID := ref.Title
			for _, pkg := range erratum.Pkglist.Packages {
				if pkg.Arch != "noarch" && pkg.Arch != "x86_64" {
					continue
				}

				advisory := types.Advisory{
					FixedVersion: constructVersion(pkg.Epoch, pkg.Version, pkg.Release),
				}
				if err := vs.dbc.PutAdvisoryDetail(tx, cveID, platformName, pkg.Name, advisory); err != nil {
					return xerrors.Errorf("failed to save Alma advisory: %w", err)
				}

				vuln := types.VulnerabilityDetail{
					Severity:    generalizeSeverity(erratum.Severity),
					References:  references,
					Title:       erratum.Title,
					Description: erratum.Description,
				}
				if err := vs.dbc.PutVulnerabilityDetail(tx, cveID, vulnerability.Alma, vuln); err != nil {
					return xerrors.Errorf("failed to save Alma vulnerability: %w", err)
				}

				// for light DB
				if err := vs.dbc.PutSeverity(tx, cveID, types.SeverityUnknown); err != nil {
					return xerrors.Errorf("failed to save Alma vulnerability severity for light: %w", err)
				}
			}
		}
	}
	return nil
}

func (vs VulnSrc) Get(release, pkgName string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, release)
	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get Alma advisories: %w", err)
	}
	return advisories, nil
}

func generalizeSeverity(severity string) types.Severity {
	switch strings.ToLower(severity) {
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

func constructVersion(epoch, version, release string) string {
	verStr := ""
	if epoch != "0" && epoch != "" {
		verStr += fmt.Sprintf("%s:", epoch)
	}
	verStr += version

	if release != "" {
		verStr += fmt.Sprintf("-%s", release)

	}
	return verStr
}
