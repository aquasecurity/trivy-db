package pypa

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	vtypes "github.com/aquasecurity/vuln-list-update/types"
)

const (
	pypaDir      = "pypa"
	platformName = "pypa"
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
	rootDir := filepath.Join(dir, "vuln-list", pypaDir)

	var osvs []vtypes.Osv

	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var osv vtypes.Osv
		if err := json.NewDecoder(r).Decode(&osv); err != nil {
			return xerrors.Errorf("failed to decode pypa json (%s): %w", path, err)
		}
		osvs = append(osvs, osv)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in pypa walk: %w", err)
	}

	if err = vs.save(osvs); err != nil {
		return xerrors.Errorf("error in pypa save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(osvs []vtypes.Osv) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, osvs)
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, osvs []vtypes.Osv) error {
	for _, osv := range osvs {
		var vulnerableVersions []string
		vulnId := getVulnId(&osv)

		firstVersion := osv.Affects.Versions[0]

		for _, rng := range osv.Affects.Ranges {
			if rng.Type == "ECOSYSTEM" && rng.Fixed != "" {
				var vulnerableVersion string
				if rng.Introduced == "" {
					vulnerableVersion = fmt.Sprintf(">=%s <%s", firstVersion, rng.Fixed)
				} else {
					vulnerableVersion = fmt.Sprintf(">=%s <%s", rng.Introduced, rng.Fixed)
				}
				vulnerableVersions = append(vulnerableVersions, vulnerableVersion)
			}
		}

		advisory := types.Advisory{
			VulnerableVersions: vulnerableVersions,
		}

		if err := vs.dbc.PutAdvisoryDetail(tx, vulnId, platformName, osv.Package.Name, advisory); err != nil {
			return xerrors.Errorf("failed to save pypa advisory: %w", err)
		}

		vuln := types.VulnerabilityDetail{
			ID:               vulnId,
			Description:      osv.Details,
			PublishedDate:    MustParse(time.RFC3339, osv.Published),
			LastModifiedDate: MustParse(time.RFC3339Nano, osv.Modified),
			Title:            osv.Id,
			//TODO references
		}

		if err := vs.dbc.PutVulnerabilityDetail(tx, osv.Id, vulnerability.Pypa, vuln); err != nil {
			return xerrors.Errorf("failed to save pypa vulnerability: %w", err)
		}

		// for light DB
		if err := vs.dbc.PutSeverity(tx, vulnId, types.SeverityUnknown); err != nil {
			return xerrors.Errorf("failed to save pypa vulnerability severity for light: %w", err)
		}
	}
	return nil
}

func (vs VulnSrc) Get(pkgName string) ([]types.Advisory, error) {
	advisories, err := vs.dbc.GetAdvisories(platformName, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get PyPA advisories: %w", err)
	}
	return advisories, nil
}

func getVulnId(osv *vtypes.Osv) string {
	if len(osv.Aliases) == 0 {
		return osv.Id
	} else {
		return osv.Aliases[0] //CVE Id
	}
}

func MustParse(layout, value string) *time.Time {
	t, err := time.Parse(layout, value)
	if err != nil {
		return nil
	}
	return &t
}
