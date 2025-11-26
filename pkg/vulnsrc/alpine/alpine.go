package alpine

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

const alpineDir = "alpine"

var (
	source = types.DataSource{
		ID:   vulnerability.Alpine,
		Name: "Alpine Secdb",
		URL:  "https://secdb.alpinelinux.org/",
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
	rootDir := filepath.Join(dir, "vuln-list", alpineDir)
	eb := oops.In("alpine").With("root_dir", rootDir)

	var advisories []advisory
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var advisory advisory
		if err := json.NewDecoder(r).Decode(&advisory); err != nil {
			return eb.With("file_path", path).Wrapf(err, "failed to decode Alpine advisory")
		}
		advisories = append(advisories, advisory)
		return nil
	})
	if err != nil {
		return eb.Wrapf(err, "walk error")
	}

	if err = vs.save(advisories); err != nil {
		return eb.Wrapf(err, "save error")
	}

	return nil
}

func (vs VulnSrc) save(advisories []advisory) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		for _, adv := range advisories {
			version := strings.TrimPrefix(adv.Distroversion, "v")
			platformName := bucket.NewAlpine(version).Name()
			eb := oops.With("version", version).With("platform", platformName)
			if err := vs.dbc.PutDataSource(tx, platformName, source); err != nil {
				return eb.Wrapf(err, "failed to put data source")
			}
			if err := vs.saveSecFixes(tx, platformName, adv.PkgName, adv.Secfixes); err != nil {
				return eb.Wrapf(err, "failed to save sec fixes")
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
			// See https://gitlab.alpinelinux.org/alpine/infra/docker/secdb/-/issues/3
			// e.g. CVE-2017-2616 (+ regression fix)
			// e.g. GHSA-h6cc-rc6q-23j4 (+regression fix)
			ids := strings.Fields(vulnID)
			// Find CVE-ID first, if not found, use GHSA-ID
			var selectedID string
			for _, id := range ids {
				id = strings.ReplaceAll(id, "CVE_", "CVE-")
				if strings.HasPrefix(id, "CVE-") {
					selectedID = id
					break // CVE-ID found, prioritize it
				} else if strings.HasPrefix(id, "GHSA-") {
					selectedID = id // Use GHSA-ID if no CVE-ID found yet
				}
			}

			if selectedID == "" {
				// No valid vulnerability ID found
				continue
			}

			if err := vs.dbc.PutAdvisoryDetail(tx, selectedID, pkgName, []string{platform}, advisory); err != nil {
				return oops.Wrapf(err, "failed to save advisory")
			}

			// for optimization
			if err := vs.dbc.PutVulnerabilityID(tx, selectedID); err != nil {
				return oops.Wrapf(err, "failed to save the vulnerability ID")
			}
		}
	}
	return nil
}

func (vs VulnSrc) Get(params db.GetParams) ([]types.Advisory, error) {
	eb := oops.In("alpine").With("release", params.Release)
	platformName := bucket.NewAlpine(params.Release).Name()
	advisories, err := vs.dbc.GetAdvisories(platformName, params.PkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get Alpine advisories")
	}
	return advisories, nil
}
