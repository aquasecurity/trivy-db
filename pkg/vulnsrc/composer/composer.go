package composer

import (
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

const composerDir = "php-security-advisories"

var (
	source = types.DataSource{
		ID:   vulnerability.PhpSecurityAdvisories,
		Name: "PHP Security Advisories Database",
		URL:  "https://github.com/FriendsOfPHP/security-advisories",
	}

	bucketName = bucket.Name(vulnerability.Composer, source.Name)
)

type RawAdvisory struct {
	Cve       string
	Title     string
	Link      string
	Reference string
	Branches  map[string]Branch
}

type Branch struct {
	Versions []string `json:",omitempty"`
}

type Advisory struct {
	VulnerabilityID string            `json:",omitempty"`
	Branches        map[string]Branch `json:",omitempty"`
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

func (vs VulnSrc) Update(dir string) (err error) {
	repoPath := filepath.Join(dir, composerDir)
	eb := oops.In("composer").With("repo_path", repoPath)
	if err := vs.update(repoPath); err != nil {
		return eb.Wrapf(err, "update error")
	}
	return nil
}

func (vs VulnSrc) update(repoPath string) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		if err := vs.dbc.PutDataSource(tx, bucketName, source); err != nil {
			return oops.Wrapf(err, "failed to put data source")
		}
		if err := vs.walk(tx, repoPath); err != nil {
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
		eb := oops.With("file_path", path)
		if err != nil {
			return eb.Wrapf(err, "walk error")
		} else if info.IsDir() || !strings.HasPrefix(info.Name(), "CVE-") {
			return nil
		}

		buf, err := os.ReadFile(path)
		if err != nil {
			return eb.Wrapf(err, "file read error")
		}

		advisory := RawAdvisory{}
		if err := yaml.Unmarshal(buf, &advisory); err != nil {
			return eb.Wrapf(err, "yaml unmarshal error")
		}

		// for detecting vulnerabilities
		vulnID := advisory.Cve
		if vulnID == "" {
			// e.g. CVE-2019-12139.yaml => CVE-2019-12139
			vulnID = strings.TrimSuffix(info.Name(), ".yaml")
		}

		var vulnerableVersions []string
		for _, branch := range advisory.Branches {
			vulnerableVersions = append(vulnerableVersions, strings.Join(branch.Versions, ", "))
		}

		a := types.Advisory{
			VulnerableVersions: vulnerableVersions,
		}

		pkgName := strings.TrimPrefix(advisory.Reference, "composer://")
		pkgName = vulnerability.NormalizePkgName(vulnerability.Composer, pkgName)

		if err = vs.dbc.PutAdvisoryDetail(tx, vulnID, pkgName, []string{bucketName}, a); err != nil {
			return eb.Wrapf(err, "failed to save advisory")
		}

		// for displaying vulnerability detail
		vuln := types.VulnerabilityDetail{
			ID:         vulnID,
			References: []string{advisory.Link},
			Title:      advisory.Title,
		}
		if err = vs.dbc.PutVulnerabilityDetail(tx, vulnID, source.ID, vuln); err != nil {
			return eb.Wrapf(err, "failed to save vulnerability detail")
		}

		// for optimization
		if err = vs.dbc.PutVulnerabilityID(tx, vulnID); err != nil {
			return eb.Wrapf(err, "failed to save vulnerability ID")
		}
		return nil
	})
}
