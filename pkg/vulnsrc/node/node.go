package node

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	bolt "github.com/etcd-io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

// https://github.com/nodejs/security-wg.git

const (
	nodeDir = "nodejs-security-wg"
)

var (
	repoPath string
)

type RawAdvisory struct {
	ID                 int
	Title              string
	ModuleName         string `json:"module_name"`
	Cves               []string
	VulnerableVersions string `json:"vulnerable_versions"`
	PatchedVersions    string `json:"patched_versions"`
	Overview           string
	Recommendation     string
	References         []string
	CvssScoreNumber    interface{} `json:"cvss_score"`
	CvssScore          float64
}

// This is for Go 1.14+ compat, to support mixed strings of CVSSScores
// In Node core CVSSScore is like: "4.8 (Medium)", Type string
// In NPM package CVSSScore is like: 4.8, Type float64
// Details: https://github.com/golang/go/issues/37308
func (ra *RawAdvisory) UnmarshalJSON(b []byte) error {
	var x struct {
		ID                 int
		Title              string
		ModuleName         string `json:"module_name"`
		Cves               []string
		VulnerableVersions string `json:"vulnerable_versions"`
		PatchedVersions    string `json:"patched_versions"`
		Overview           string
		Recommendation     string
		References         []string
		CvssScore          float64
		CvssScoreNumber    json.RawMessage `json:"cvss_score"`
	}

	if err := json.Unmarshal(b, &x); err != nil {
		return err
	}

	// populate other sane fields first
	ra.ID = x.ID
	ra.Title = x.Title
	ra.ModuleName = x.ModuleName
	ra.Cves = x.Cves
	ra.VulnerableVersions = x.VulnerableVersions
	ra.PatchedVersions = x.PatchedVersions
	ra.Overview = x.Overview
	ra.Recommendation = x.Recommendation
	ra.References = x.References

	// CVSS score is missing
	if len(x.CvssScoreNumber) <= 0 {
		ra.CvssScore = -1
		return nil
	}

	var n json.Number
	if err := json.Unmarshal(x.CvssScoreNumber, &n); err == nil {
		ra.CvssScore, _ = n.Float64()
		return nil
	}

	var s string
	if err := json.Unmarshal(x.CvssScoreNumber, &s); err != nil {
		return err
	}
	ra.CvssScore, _ = strconv.ParseFloat(strings.Split(s, " ")[0], 64)
	return nil
}

type Advisory struct {
	VulnerabilityID    string `json:",omitempty"`
	VulnerableVersions string `json:",omitempty"`
	PatchedVersions    string `json:",omitempty"`
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
	repoPath = filepath.Join(dir, nodeDir)
	if err := vs.update(repoPath); err != nil {
		return xerrors.Errorf("failed to update node vulnerabilities: %w", err)
	}
	return nil
}

func (vs VulnSrc) update(repoPath string) error {
	root := filepath.Join(repoPath, "vuln")

	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		if err := vs.walk(tx, root); err != nil {
			return xerrors.Errorf("failed to walk node advisories: %w", err)
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("batch update failed: %w", err)
	}
	return nil
}

func (vs VulnSrc) walk(tx *bolt.Tx, root string) error {
	return filepath.Walk(filepath.Join(repoPath, "vuln"), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".json") {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		return vs.commit(tx, f)
	})
}

func (vs VulnSrc) commit(tx *bolt.Tx, f *os.File) error {
	advisory := RawAdvisory{}
	b, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(b, &advisory); err != nil {
		return err
	}

	// Node.js itself
	if advisory.ModuleName == "" {
		return nil
	}
	advisory.ModuleName = strings.ToLower(advisory.ModuleName)

	vulnerabilityIDs := advisory.Cves
	if len(vulnerabilityIDs) == 0 {
		vulnerabilityIDs = []string{fmt.Sprintf("NSWG-ECO-%d", advisory.ID)}
	}

	a := Advisory{
		VulnerableVersions: advisory.VulnerableVersions,
		PatchedVersions:    advisory.PatchedVersions,
	}
	for _, vulnID := range vulnerabilityIDs {
		// for detecting vulnerabilities
		err := vs.dbc.PutAdvisory(tx, vulnerability.NodejsSecurityWg, advisory.ModuleName, vulnID, a)
		if err != nil {
			return xerrors.Errorf("failed to save node advisory: %w", err)
		}

		// for displaying vulnerability detail
		vuln := types.VulnerabilityDetail{
			ID:          vulnID,
			CvssScore:   advisory.CvssScore,
			References:  advisory.References,
			Title:       advisory.Title,
			Description: advisory.Overview,
		}
		if err = vs.dbc.PutVulnerabilityDetail(tx, vulnID, vulnerability.NodejsSecurityWg, vuln); err != nil {
			return xerrors.Errorf("failed to save node vulnerability detail: %w", err)
		}

		if err := vs.dbc.PutSeverity(tx, vulnID, types.SeverityUnknown); err != nil {
			return xerrors.Errorf("failed to save node vulnerability severity: %w", err)
		}
	}

	return nil
}

func (vs VulnSrc) Get(pkgName string) ([]Advisory, error) {
	advisories, err := vs.dbc.ForEachAdvisory(vulnerability.NodejsSecurityWg, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to iterate node vulnerabilities: %w", err)
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
