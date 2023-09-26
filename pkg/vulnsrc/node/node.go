package node

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	nodeDir = "nodejs-security-wg"
)

var (
	source = types.DataSource{
		ID:   vulnerability.NodejsSecurityWg,
		Name: "Node.js Ecosystem Security Working Group",
		URL:  "https://github.com/nodejs/security-wg",
	}

	bucketName = bucket.Name(vulnerability.Npm, source.Name)
)

type Number struct {
	Value float64
}

// This is for Go 1.14+ compat, to support mixed strings of CVSSScores
// In Node core CVSSScore is like: "4.8 (Medium)", Type string
// In NPM package CVSSScore is like: 4.8, Type float64
// Details: https://github.com/golang/go/issues/37308
func (n *Number) UnmarshalJSON(b []byte) error {
	var data interface{}
	if err := json.Unmarshal(b, &data); err != nil {
		return err
	}

	switch v := data.(type) {
	case float64:
		n.Value = v
	case string:
		f, err := strconv.ParseFloat(strings.Split(v, " ")[0], 64)
		if err != nil {
			return err
		}
		n.Value = f
	default: // it can be null: https://github.com/nodejs/security-wg/blob/master/vuln/npm/334.json
		n.Value = -1
	}
	return nil
}

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
	CvssScoreNumber    Number `json:"cvss_score"`
	CvssScore          float64
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
	repoPath := filepath.Join(dir, nodeDir)
	if err := vs.update(repoPath); err != nil {
		return xerrors.Errorf("failed to update node vulnerabilities: %w", err)
	}
	return nil
}

func (vs VulnSrc) update(repoPath string) error {
	root := filepath.Join(repoPath, "vuln")

	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		if err := vs.dbc.PutDataSource(tx, bucketName, source); err != nil {
			return xerrors.Errorf("failed to put data source: %w", err)
		}
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
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
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
	var err error
	if err = json.NewDecoder(f).Decode(&advisory); err != nil {
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

	adv := convertToGenericAdvisory(advisory)
	for _, vulnID := range vulnerabilityIDs {
		// for detecting vulnerabilities
		err = vs.dbc.PutAdvisoryDetail(tx, vulnID, advisory.ModuleName, []string{bucketName}, adv)
		if err != nil {
			return xerrors.Errorf("failed to save node advisory: %w", err)
		}

		// If an advisory is 0 override with -1
		// https://github.com/nodejs/security-wg/pull/91/files
		if advisory.CvssScoreNumber.Value <= 0 {
			advisory.CvssScoreNumber.Value = -1
		}

		// for displaying vulnerability detail
		vuln := types.VulnerabilityDetail{
			ID:          vulnID,
			CvssScore:   advisory.CvssScoreNumber.Value,
			References:  advisory.References,
			Title:       advisory.Title,
			Description: advisory.Overview,
		}
		if err = vs.dbc.PutVulnerabilityDetail(tx, vulnID, source.ID, vuln); err != nil {
			return xerrors.Errorf("failed to save node vulnerability detail: %w", err)
		}

		// for optimization
		if err = vs.dbc.PutVulnerabilityID(tx, vulnID); err != nil {
			return xerrors.Errorf("failed to save the vulnerability ID: %w", err)
		}
	}

	return nil
}

func convertToGenericAdvisory(advisory RawAdvisory) types.Advisory {
	var vulnerable, patched []string
	if advisory.VulnerableVersions != "" {
		for _, ver := range strings.Split(advisory.VulnerableVersions, "||") {
			vulnerable = append(vulnerable, strings.TrimSpace(ver))
		}
	}
	if advisory.PatchedVersions != "" {
		for _, ver := range strings.Split(advisory.PatchedVersions, "||") {
			patched = append(patched, strings.TrimSpace(ver))
		}
	}

	return types.Advisory{
		VulnerableVersions: vulnerable,
		PatchedVersions:    patched,
	}
}
