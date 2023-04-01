package chainguard

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
	chainguardDir = "chainguard"
	distroName    = "chainguard"
)

var (
	source = types.DataSource{
		ID:   vulnerability.Chainguard,
		Name: "Chainguard Security Data",
		URL:  "https://packages.cgr.dev/chainguard/security.json",
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
	rootDir := filepath.Join(dir, "vuln-list", chainguardDir)
	var advisories []advisory
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var advisory advisory
		if err := json.NewDecoder(r).Decode(&advisory); err != nil {
			return xerrors.Errorf("failed to decode Chainguard advisory: %w", err)
		}
		advisories = append(advisories, advisory)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in Chainguard walk: %w", err)
	}

	if err = vs.save(advisories); err != nil {
		return xerrors.Errorf("error in Chainguard save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(advisories []advisory) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		for _, adv := range advisories {
			bucket := distroName
			if err := vs.dbc.PutDataSource(tx, bucket, source); err != nil {
				return xerrors.Errorf("failed to put data source: %w", err)
			}
			if err := vs.saveSecFixes(tx, distroName, adv.PkgName, adv.Secfixes); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in db batch update: %w", err)
	}
	return nil
}

func (vs VulnSrc) saveSecFixes(tx *bolt.Tx, platform, pkgName string, secfixes map[string][]string) error {
	for fixedVersion, vulnIDs := range secfixes {
		advisory := types.Advisory{
			FixedVersion: fixedVersion,
		}

		for _, vulnID := range vulnIDs {
			if !strings.HasPrefix(vulnID, "CVE-") {
				continue
			}

			if err := vs.dbc.PutAdvisoryDetail(tx, vulnID, pkgName, []string{platform}, advisory); err != nil {
				return xerrors.Errorf("failed to save Chainguard advisory: %w", err)
			}

			// for optimization
			if err := vs.dbc.PutVulnerabilityID(tx, vulnID); err != nil {
				return xerrors.Errorf("failed to save the vulnerability ID: %w", err)
			}
		}
	}

	return nil
}

func (vs VulnSrc) Get(_, pkgName string) ([]types.Advisory, error) {
	bucket := distroName
	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get Chainguard advisories: %w", err)
	}
	return advisories, nil
}
