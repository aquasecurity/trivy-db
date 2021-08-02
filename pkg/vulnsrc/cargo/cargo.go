package cargo

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/types"

	"github.com/BurntSushi/toml"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

// https://github.com/RustSec/advisory-db.git

const (
	cargoDir = "rust-advisory-db"
)

type Lockfile struct {
	RawAdvisory `toml:"advisory"`
	RawVersion  `toml:"versions"`
}

type RawAdvisory struct {
	Id          string
	Package     string
	Title       string `toml:"title"`
	Url         string
	Date        string
	Description string
	Keywords    []string
}

type RawVersion struct {
	PatchedVersions    []string `toml:"patched"`
	UnaffectedVersions []string `toml:"unaffected"`
}

type Advisory struct {
	VulnerabilityID    string   `json:",omitempty"`
	PatchedVersions    []string `json:",omitempty"`
	UnaffectedVersions []string `json:",omitempty"`
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
	return vulnerability.Cargo
}

func (vs VulnSrc) Update(dir string) (err error) {
	repoPath := filepath.Join(dir, cargoDir)
	if err := vs.update(repoPath); err != nil {
		return xerrors.Errorf("failed to update rust vulnerabilities: %w", err)
	}
	return nil
}

func (vs VulnSrc) update(repoPath string) error {
	root := filepath.Join(repoPath, "crates")

	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		if err := vs.walk(tx, root); err != nil {
			return xerrors.Errorf("failed to walk rust advisories: %w", err)
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
		if info.IsDir() {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return xerrors.Errorf("failed to open a file (%s): %w", path, err)
		}
		defer f.Close()

		codeBlock, title, description, err := parseAdvisoryMarkdown(f)
		if err != nil {
			return xerrors.Errorf("failed to parse markdown: %w", err)
		}

		advisory := Lockfile{}
		err = toml.Unmarshal([]byte(codeBlock), &advisory)
		if err != nil {
			return xerrors.Errorf("failed to unmarshal TOML (%s): %w", path, err)
		}
		advisory.Title = title
		advisory.Description = description

		// for detecting vulnerabilities
		a := Advisory{PatchedVersions: advisory.PatchedVersions,
			UnaffectedVersions: advisory.UnaffectedVersions}
		err = vs.dbc.PutAdvisoryDetail(tx, advisory.Id, vulnerability.RustSec, advisory.Package, a)
		if err != nil {
			return xerrors.Errorf("failed to save rust advisory: %w", err)
		}

		// for displaying vulnerability detail
		vuln := types.VulnerabilityDetail{
			ID:          advisory.Id,
			References:  []string{advisory.Url},
			Title:       advisory.Title,
			Description: advisory.Description,
		}
		if err = vs.dbc.PutVulnerabilityDetail(tx, advisory.Id, vulnerability.RustSec, vuln); err != nil {
			return xerrors.Errorf("failed to save rust vulnerability detail: %w", err)
		}

		if err = vs.dbc.PutSeverity(tx, advisory.Id, types.SeverityUnknown); err != nil {
			return xerrors.Errorf("failed to save rust vulnerability severity: %w", err)
		}

		return nil
	})
}

func (vs VulnSrc) Get(pkgName string) ([]Advisory, error) {
	advisories, err := vs.dbc.ForEachAdvisory(vulnerability.RustSec, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to iterate rust vulnerabilities: %w", err)
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

// https://github.com/RustSec/advisory-db/issues/414#issuecomment-702197689
func parseAdvisoryMarkdown(r io.Reader) (string, string, string, error) {
	scanner := bufio.NewScanner(r)
	var isCodeBlock, isTitle bool
	var codeBlock, title, description string

	for scanner.Scan() {
		line := scanner.Text()
		switch {
		// TOML
		case strings.HasPrefix(line, "```toml"):
			isCodeBlock = true
		case strings.HasPrefix(line, "```"):
			isCodeBlock = false
		case isCodeBlock:
			codeBlock += line + "\n"

		// Title/Description
		case strings.HasPrefix(line, "#"):
			isTitle = true
			title = strings.TrimSpace(line[1:])
		case isTitle:
			description += line + "\n"
		}
	}

	if err := scanner.Err(); err != nil {
		return "", "", "", xerrors.Errorf("reading error: %w", err)
	}

	return strings.TrimSpace(codeBlock), title, strings.TrimSpace(description), nil
}
