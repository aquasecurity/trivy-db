package bundler

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v2"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

// https://github.com/rubysec/ruby-advisory-db.git

const (
	bundlerDir = "ruby-advisory-db"
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

func (vs VulnSrc) Name() string {
	return vulnerability.RubySec
}

func (vs VulnSrc) Update(dir string) error {
	repoPath := filepath.Join(dir, bundlerDir)
	if err := vs.update(repoPath); err != nil {
		return xerrors.Errorf("failed to update bundler vulnerabilities: %w", err)
	}
	return nil
}

func (vs VulnSrc) update(repoPath string) error {
	root := filepath.Join(repoPath, "gems")

	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		if err := vs.walk(tx, root); err != nil {
			return xerrors.Errorf("failed to walk ruby advisories: %w", err)
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("batch update failed: %w", err)
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

	buf, err := ioutil.ReadFile(path)
	if err != nil {
		return xerrors.Errorf("failed to read a file: %w", err)
	}

	advisory := RawAdvisory{}
	err = yaml.Unmarshal(buf, &advisory)
	if err != nil {
		return xerrors.Errorf("failed to unmarshal YAML: %w", err)
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

	// for detecting vulnerabilities
	a := Advisory{
		PatchedVersions:    advisory.PatchedVersions,
		UnaffectedVersions: advisory.UnaffectedVersions,
	}
	err = vs.dbc.PutAdvisoryDetail(tx, vulnerabilityID, vulnerability.RubySec, advisory.Gem, a)
	if err != nil {
		return xerrors.Errorf("failed to save ruby advisory: %w", err)
	}

	// for displaying vulnerability detail
	vuln := types.VulnerabilityDetail{
		ID:          vulnerabilityID,
		CvssScore:   advisory.CvssV2,
		CvssScoreV3: advisory.CvssV3,
		References:  append([]string{advisory.Url}, advisory.Related.Url...),
		Title:       advisory.Title,
		Description: advisory.Description,
	}
	if err = vs.dbc.PutVulnerabilityDetail(tx, vulnerabilityID, vulnerability.RubySec, vuln); err != nil {
		return xerrors.Errorf("failed to save ruby vulnerability detail: %w", err)
	}

	if err := vs.dbc.PutSeverity(tx, vulnerabilityID, types.SeverityUnknown); err != nil {
		return xerrors.Errorf("failed to save ruby vulnerability severity: %w", err)
	}
	return nil
}

func (vs VulnSrc) Get(pkgName string) ([]Advisory, error) {
	advisories, err := vs.dbc.ForEachAdvisory(vulnerability.RubySec, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to iterate ruby vulnerabilities: %w", err)
	}

	var results []Advisory
	for vulnID, a := range advisories {
		var advisory Advisory
		if err = json.Unmarshal(a, &advisory); err != nil {
			return nil, xerrors.Errorf("failed to unmarshal advisory JSON: %w", err)
		}
		advisory.VulnerabilityID = vulnID
		results = append(results, advisory)
	}
	return results, nil
}
