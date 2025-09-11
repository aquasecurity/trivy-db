package chainguard

import (
	"encoding/json"
	"io"
	"path/filepath"
	"strings"

	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const chainguardDir = "chainguard"

var (
	platformName = bucket.NewChainguard("").Name()
	source       = types.DataSource{
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
	eb := oops.With("root_dir", rootDir)

	var advisories []advisory
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		eb := eb.With("file_path", path)

		var advisory advisory
		if err := json.NewDecoder(r).Decode(&advisory); err != nil {
			return eb.Wrapf(err, "json decode error")
		}
		advisories = append(advisories, advisory)
		return nil
	})
	if err != nil {
		return eb.Wrapf(err, "walk error")
	}

	if err = vs.save(advisories); err != nil {
		return eb.Wrapf(err, "save advisories error")
	}

	return nil
}

func (vs VulnSrc) save(advisories []advisory) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		for _, adv := range advisories {
			if err := vs.dbc.PutDataSource(tx, platformName, source); err != nil {
				return oops.Wrapf(err, "failed to put data source")
			}
			if err := vs.saveSecFixes(tx, platformName, adv.PkgName, adv.Secfixes); err != nil {
				return oops.Wrapf(err, "save sec fixes error")
			}
		}
		return nil
	})
	if err != nil {
		return oops.Wrapf(err, "db batch update error")
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
				return oops.Wrapf(err, "failed to save advisory")
			}

			// for optimization
			if err := vs.dbc.PutVulnerabilityID(tx, vulnID); err != nil {
				return oops.Wrapf(err, "failed to save the vulnerability ID")
			}
		}
	}

	return nil
}

func (vs VulnSrc) Get(params db.GetParams) ([]types.Advisory, error) {
	eb := oops.In("chainguard")
	advisories, err := vs.dbc.GetAdvisories(platformName, params.PkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get advisories")
	}
	return advisories, nil
}
