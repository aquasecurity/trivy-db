package minimos

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
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	distroName = "minimos"
)

var (
	source = types.DataSource{
		ID:   vulnerability.MinimOS,
		Name: "MinimOS Security Data",
		URL:  "https://packages.mini.dev/advisories/secdb/security.json",
	}
)

type advisory struct {
	PkgName  string              `json:"name"`
	Secfixes map[string][]string `json:"secfixes"`
}

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
	rootDir := filepath.Join(dir, "vuln-list", distroName)
	eb := oops.In(string(source.ID)).With("root_dir", rootDir)

	var advisories []advisory
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var advisory advisory
		if err := json.NewDecoder(r).Decode(&advisory); err != nil {
			return eb.With("file_path", path).Wrapf(err, "json decode error")
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
		if err := vs.dbc.PutDataSource(tx, distroName, source); err != nil {
			return oops.Wrapf(err, "failed to put data source")
		}
		for _, adv := range advisories {
			if err := vs.saveSecFixes(tx, distroName, adv.PkgName, adv.Secfixes); err != nil {
				return oops.Wrapf(err, "failed to save sec fixes")
			}
		}
		return nil
	})
	if err != nil {
		return oops.Wrapf(err, "batch update failed")
	}
	return nil
}

func (vs VulnSrc) saveSecFixes(tx *bolt.Tx, platform, pkgName string, secfixes map[string][]string) error {
	for fixedVersion, vulnIDs := range secfixes {
		// Fixed version is "0" when package doesn't contain specified vulnerabilities.
		if fixedVersion == "0" {
			continue
		}
		adv := types.Advisory{
			FixedVersion: fixedVersion,
		}
		for _, vulnID := range vulnIDs {
			// Only include CVEs to as other GHSA entries are aliases to the same vulnerabilities
			// See discussion: https://github.com/aquasecurity/trivy-db/pull/521#discussion_r2097919923
			if !strings.HasPrefix(vulnID, "CVE-") {
				continue
			}

			if err := vs.dbc.PutAdvisoryDetail(tx, vulnID, pkgName, []string{platform}, adv); err != nil {
				return oops.Wrapf(err, "failed to save advisory")
			}

			// Optimization: store only vendor-detected vulnerabilities from NVD
			if err := vs.dbc.PutVulnerabilityID(tx, vulnID); err != nil {
				return oops.Wrapf(err, "failed to save the vulnerability ID")
			}
		}
	}
	return nil
}

func (vs VulnSrc) Get(params db.GetParams) ([]types.Advisory, error) {
	eb := oops.In(string(source.ID))
	bucket := distroName
	advisories, err := vs.dbc.GetAdvisories(bucket, params.PkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get advisories")
	}
	return advisories, nil
}
