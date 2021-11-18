package composer

import (
	"encoding/json"
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

// https://github.com/FriendsOfPHP/security-advisories

const (
	composerDir = "php-security-advisories"
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

func (vs VulnSrc) Name() string {
	return vulnerability.PhpSecurityAdvisories
}

func (vs VulnSrc) Update(dir string) (err error) {
	repoPath := filepath.Join(dir, composerDir)
	if err := vs.update(repoPath); err != nil {
		return xerrors.Errorf("failed to update compose vulnerabilities: %w", err)
	}
	return nil
}

func (vs VulnSrc) update(repoPath string) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		if err := vs.walk(tx, repoPath); err != nil {
			return xerrors.Errorf("failed to walk compose advisories: %w", err)
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
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasPrefix(info.Name(), "CVE-") {
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

		// for detecting vulnerabilities
		vulnerabilityID := advisory.Cve
		if vulnerabilityID == "" {
			// e.g. CVE-2019-12139.yaml => CVE-2019-12139
			vulnerabilityID = strings.TrimSuffix(info.Name(), ".yaml")
		}

		a := Advisory{Branches: advisory.Branches}
		err = vs.dbc.PutAdvisoryDetail(tx, vulnerabilityID, vulnerability.PhpSecurityAdvisories, advisory.Reference, a)
		if err != nil {
			return xerrors.Errorf("failed to save php advisory: %w", err)
		}

		// for displaying vulnerability detail
		vuln := types.VulnerabilityDetail{
			ID:         vulnerabilityID,
			References: []string{advisory.Link},
			Title:      advisory.Title,
		}
		if err = vs.dbc.PutVulnerabilityDetail(tx, vulnerabilityID, vulnerability.PhpSecurityAdvisories, vuln); err != nil {
			return xerrors.Errorf("failed to save php vulnerability detail: %w", err)
		}

		if err := vs.dbc.PutSeverity(tx, vulnerabilityID, types.SeverityUnknown); err != nil {
			return xerrors.Errorf("failed to save php vulnerability severity: %w", err)
		}
		return nil
	})
}

func (vs VulnSrc) Get(pkgName string) ([]Advisory, error) {
	advisories, err := vs.dbc.ForEachAdvisory(vulnerability.PhpSecurityAdvisories, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to iterate php vulnerabilities: %w", err)
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
