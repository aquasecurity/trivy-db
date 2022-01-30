package archlinux

import (
	"encoding/json"
	"io"
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
	archLinuxDir = "arch-linux"
	platformName = "archlinux"
)

var (
	source = types.DataSource{
		ID:   vulnerability.ArchLinux,
		Name: "Arch Linux Vulnerable issues",
		URL:  "https://security.archlinux.org/",
	}
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
	return source.ID
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", archLinuxDir)

	var avgs []ArchVulnGroup

	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var avg ArchVulnGroup
		if err := json.NewDecoder(r).Decode(&avg); err != nil {
			return xerrors.Errorf("failed to decode arch linux json (%s): %w", path, err)
		}
		avgs = append(avgs, avg)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in arch linux walk: %w", err)
	}

	if err = vs.save(avgs); err != nil {
		return xerrors.Errorf("error in arch linux save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(avgs []ArchVulnGroup) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		if err := vs.dbc.PutDataSource(tx, platformName, source); err != nil {
			return xerrors.Errorf("failed to put data source: %w", err)
		}
		if err := vs.commit(tx, avgs); err != nil {
			return xerrors.Errorf("commit error: %w", err)
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, avgs []ArchVulnGroup) error {
	for _, avg := range avgs {
		for _, cveId := range avg.Issues {
			advisory := types.Advisory{
				FixedVersion:    avg.Fixed,
				AffectedVersion: avg.Affected,
			}

			for _, pkg := range avg.Packages {
				if err := vs.dbc.PutAdvisoryDetail(tx, cveId, pkg, []string{platformName}, advisory); err != nil {
					return xerrors.Errorf("failed to save arch linux advisory: %w", err)
				}

				vuln := types.VulnerabilityDetail{
					Severity: convertSeverity(avg.Severity),
				}
				if err := vs.dbc.PutVulnerabilityDetail(tx, cveId, source.ID, vuln); err != nil {
					return xerrors.Errorf("failed to save arch linux vulnerability: %w", err)
				}

				// for optimization
				if err := vs.dbc.PutVulnerabilityID(tx, cveId); err != nil {
					return xerrors.Errorf("failed to save the vulnerability ID: %w", err)
				}
			}

		}
	}
	return nil
}

func (vs VulnSrc) Get(pkgName string) ([]types.Advisory, error) {
	advisories, err := vs.dbc.GetAdvisories(platformName, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get Arch Linux advisories: %w", err)
	}
	return advisories, nil
}

func convertSeverity(sev string) types.Severity {
	severity, _ := types.NewSeverity(strings.ToUpper(sev))
	return severity
}
