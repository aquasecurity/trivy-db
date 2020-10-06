package cargo

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
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

// https://github.com/RustSec/advisory-db/issues/414#issuecomment-702197689
var regexAdvisoryMarkdown = regexp.MustCompile(
	`(?sm)^\x60\x60\x60toml\s*?$(.*?)^\x60\x60\x60\s*?$\s*^#\s*([^\r\n]+)\s*?$(.*)`)

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
		buf, err := ioutil.ReadFile(path)
		if err != nil {
			return xerrors.Errorf("failed to read a file(%s): %w", path, err)
		}
		codeBlock, title, description, err := parseAdvisoryMarkdown(string(buf))
		if err != nil {
			return xerrors.Errorf("failed to parse V3 advisory data(%s): %w", path, err)
		}

		advisory := Lockfile{}
		err = toml.Unmarshal([]byte(codeBlock), &advisory)
		if err != nil {
			return xerrors.Errorf("failed to unmarshal TOML(%s): %w", path, err)
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

		if err := vs.dbc.PutSeverity(tx, advisory.Id, types.SeverityUnknown); err != nil {
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

func parseAdvisoryMarkdown(src string) (codeBlock, title, description string, err error) {
	matches := regexAdvisoryMarkdown.FindAllStringSubmatch(src, -1)
	if len(matches) != 1 || len(matches[0]) != 4 {
		err = xerrors.New("invalid V3 advisory format data")
		return
	}
	match := matches[0]
	codeBlock = strings.TrimSpace(match[1])
	title = strings.TrimSpace(match[2])
	description = strings.TrimSpace(match[3])
	return
}
