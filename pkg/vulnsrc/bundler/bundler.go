package bundler

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"
	"gopkg.in/yaml.v2"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const bundlerDir = "ruby-advisory-db"

var (
	source = types.DataSource{
		ID:   vulnerability.RubySec,
		Name: "Ruby Advisory Database",
		URL:  "https://github.com/rubysec/ruby-advisory-db",
	}

	bucketName = bucket.Name(vulnerability.RubyGems, source.Name)
)

type RawAdvisory struct {
	Gem                string
	Cve                string
	Osvdb              string
	Ghsa               string
	Title              string
	Url                string
	Description        string
	CvssV2             float64  `yaml:"cvss_v2"`
	CvssV3             float64  `yaml:"cvss_v3"`
	PatchedVersions    []string `yaml:"patched_versions"`
	UnaffectedVersions []string `yaml:"unaffected_versions"`
	Related            Related
}

type Advisory struct {
	VulnerabilityID    string   `json:",omitempty"`
	PatchedVersions    []string `json:",omitempty"`
	UnaffectedVersions []string `json:",omitempty"`
}

type Related struct {
	Cve []string
	Url []string
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
	repoPath := filepath.Join(dir, bundlerDir)
	eb := oops.In("bundler").With("repo_path", repoPath)
	if err := vs.update(repoPath); err != nil {
		return eb.Wrapf(err, "update error")
	}
	return nil
}

func (vs VulnSrc) update(repoPath string) error {
	root := filepath.Join(repoPath, "gems")

	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		if err := vs.dbc.PutDataSource(tx, bucketName, source); err != nil {
			return oops.Wrapf(err, "failed to put data source")
		}

		if err := vs.walk(tx, root); err != nil {
			return oops.Wrapf(err, "walk error")
		}
		return nil
	})
	if err != nil {
		return oops.Wrapf(err, "batch update failed")
	}
	return nil
}

func (vs VulnSrc) walk(tx *bolt.Tx, root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		return vs.walkFunc(err, info, path, tx)
	})
}

func (vs VulnSrc) walkFunc(err error, info os.FileInfo, path string, tx *bolt.Tx) error {
	if err != nil {
		return err
	}
	if info.IsDir() {
		return nil
	}
	if strings.HasPrefix(strings.ToUpper(info.Name()), "OSVDB") {
		return nil
	}

	eb := oops.With("file_path", path)

	buf, err := os.ReadFile(path)
	if err != nil {
		return eb.Wrapf(err, "file read error")
	}

	advisory := RawAdvisory{}
	err = yaml.Unmarshal(buf, &advisory)
	if err != nil {
		return eb.Wrapf(err, "yaml unmarshal error")
	}
	if strings.Contains(strings.ToLower(advisory.Url), "osvdb.org") {
		advisory.Url = ""
	}

	var vulnerabilityID string
	if advisory.Cve != "" {
		vulnerabilityID = fmt.Sprintf("CVE-%s", advisory.Cve)
	} else if advisory.Ghsa != "" {
		vulnerabilityID = fmt.Sprintf("GHSA-%s", advisory.Ghsa)
	} else {
		return nil
	}

	eb = eb.With("vuln_id", vulnerabilityID)

	// for detecting vulnerabilities
	a := types.Advisory{
		PatchedVersions:    advisory.PatchedVersions,
		UnaffectedVersions: advisory.UnaffectedVersions,
	}

	if err = vs.dbc.PutAdvisoryDetail(tx, vulnerabilityID, advisory.Gem, []string{bucketName}, a); err != nil {
		return eb.With("package_name", advisory.Gem).With("bucket_name", bucketName).Wrapf(err, "failed to save advisory")
	}

	// for displaying vulnerability detail
	vuln := types.VulnerabilityDetail{
		CvssScore:   advisory.CvssV2,
		CvssScoreV3: advisory.CvssV3,
		References:  append([]string{advisory.Url}, advisory.Related.Url...),
		Title:       advisory.Title,
		Description: advisory.Description,
	}

	if err = vs.dbc.PutVulnerabilityDetail(tx, vulnerabilityID, source.ID, vuln); err != nil {
		return eb.Wrapf(err, "failed to save vulnerability detail")
	}

	// for optimization
	if err = vs.dbc.PutVulnerabilityID(tx, vulnerabilityID); err != nil {
		return eb.Wrapf(err, "failed to save vulnerability ID")
	}
	return nil
}
