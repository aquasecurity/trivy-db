package minimos

import (
	"encoding/json"
	"io"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/go-version/pkg/version"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const minimosDir = "minimos"

var (
	platformName = bucket.NewMinimOS("").Name()
	source       = types.DataSource{
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
	rootDir := filepath.Join(dir, "vuln-list", minimosDir)
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
		if err := vs.dbc.PutDataSource(tx, platformName, source); err != nil {
			return oops.Wrapf(err, "failed to put data source")
		}
		for _, adv := range advisories {
			if err := vs.saveSecFixes(tx, platformName, adv.PkgName, adv.Secfixes); err != nil {
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
	// The same CVE can be listed under more than one fixed version in the secdb
	// feed, and every write lands on the same (CVE, package) key, overwriting the
	// previous value. Keep the highest version, and write the advisories in a
	// deterministic order, so the stored value no longer depends on map
	// iteration order.
	// See https://github.com/aquasecurity/trivy-db/issues/699
	fixedVersions := make(map[string]string)
	for fixedVersion, vulnIDs := range secfixes {
		// Fixed version is "0" when package doesn't contain specified vulnerabilities.
		if fixedVersion == "0" {
			continue
		}
		for _, vulnID := range vulnIDs {
			// Only include CVEs to as other GHSA entries are aliases to the same vulnerabilities
			// See discussion: https://github.com/aquasecurity/trivy-db/pull/521#discussion_r2097919923
			if !strings.HasPrefix(vulnID, "CVE-") {
				continue
			}
			if cur, ok := fixedVersions[vulnID]; ok {
				fixedVersions[vulnID] = higherFixedVersion(cur, fixedVersion)
			} else {
				fixedVersions[vulnID] = fixedVersion
			}
		}
	}

	for _, cveID := range slices.Sorted(maps.Keys(fixedVersions)) {
		adv := types.Advisory{
			FixedVersion: fixedVersions[cveID],
		}
		if err := vs.dbc.PutAdvisoryDetail(tx, cveID, pkgName, []string{platform}, adv); err != nil {
			return oops.Wrapf(err, "failed to save advisory")
		}

		// Optimization: store only vendor-detected vulnerabilities from NVD
		if err := vs.dbc.PutVulnerabilityID(tx, cveID); err != nil {
			return oops.Wrapf(err, "failed to save the vulnerability ID")
		}
	}
	return nil
}

// higherFixedVersion returns the fixed version to keep when the same CVE is
// listed under both a and b. Versions the parser rejects fall back to
// lexicographic order so the result never depends on map iteration order.
func higherFixedVersion(a, b string) string {
	pa, errA := version.Parse(a)
	pb, errB := version.Parse(b)
	if errA != nil || errB != nil {
		if a >= b {
			return a
		}
		return b
	}
	if pa.LessThan(pb) {
		return b
	}
	return a
}
func (vs VulnSrc) Get(params db.GetParams) ([]types.Advisory, error) {
	eb := oops.In(string(source.ID))
	advisories, err := vs.dbc.GetAdvisories(platformName, params.PkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get advisories")
	}
	return advisories, nil
}
