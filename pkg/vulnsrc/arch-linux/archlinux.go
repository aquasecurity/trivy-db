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

type VulnSrc struct {
	dbc db.Operation
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Name() string {
	return vulnerability.ArchLinux
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
		return vs.commit(tx, avgs)
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
				if err := vs.dbc.PutAdvisoryDetail(tx, cveId, platformName, pkg, advisory); err != nil {
					return xerrors.Errorf("failed to save arch linux advisory: %w", err)
				}

				vuln := types.VulnerabilityDetail{
					Severity: convertSeverity(avg.Severity),
				}
				if err := vs.dbc.PutVulnerabilityDetail(tx, cveId, vulnerability.ArchLinux, vuln); err != nil {
					return xerrors.Errorf("failed to save arch linux vulnerability: %w", err)
				}

				// for light DB
				if err := vs.dbc.PutSeverity(tx, cveId, types.SeverityUnknown); err != nil {
					return xerrors.Errorf("failed to save arch linux vulnerability severity for light: %w", err)
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
