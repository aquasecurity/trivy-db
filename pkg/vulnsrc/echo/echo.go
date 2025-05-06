package echo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

// VulnInfo holds the vulnerability details
type VulnInfo struct {
	FixedVersion string `json:"fixed_version"`
	Severity     string `json:"severity"`
}

// Advisory is a map of CVE IDs to vulnerability information
type Advisory map[string]VulnInfo

const (
	echoDir    = "echo"
	distroName = "echo"
)

var (
	source = types.DataSource{
		ID:   vulnerability.Echo,
		Name: "Echo",
		URL:  "https://advisory.echohq.com/data.json",
	}
)

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
	rootDir := filepath.Join(dir, "vuln-list", echoDir)
	eb := oops.In(string(source.ID)).With("root_dir", rootDir)

	entries, err := os.ReadDir(rootDir)
	if err != nil {
		return eb.Wrapf(err, "failed to read directory")
	}

	advisoryMap := make(map[string]Advisory)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filePath := filepath.Join(rootDir, entry.Name())
		f, err := os.Open(filePath)
		if err != nil {
			return eb.With("file_path", filePath).Wrapf(err, "failed to open file")
		}
		defer f.Close()

		pkgName := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		var advisory Advisory
		if err := json.NewDecoder(f).Decode(&advisory); err != nil {
			return eb.With("file_path", filePath).Wrapf(err, "json decode error")
		}
		advisoryMap[pkgName] = advisory
	}

	if err = vs.save(advisoryMap); err != nil {
		return eb.Wrapf(err, "save error")
	}

	return nil
}

func (vs VulnSrc) save(advisoryMap map[string]Advisory) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		if err := vs.dbc.PutDataSource(tx, distroName, source); err != nil {
			return oops.Wrapf(err, "failed to put data source")
		}
		for pkgName, advisory := range advisoryMap {
			if err := vs.saveVulnerabilities(tx, pkgName, advisory); err != nil {
				return oops.Wrapf(err, "failed to save vulnerabilities")
			}
		}
		return nil
	})
	if err != nil {
		return oops.Wrapf(err, "batch update failed")
	}
	return nil
}

func (vs VulnSrc) saveVulnerabilities(tx *bolt.Tx, pkgName string, advisory Advisory) error {
	for cveID, vulnInfo := range advisory {
		adv := types.Advisory{
			FixedVersion: vulnInfo.FixedVersion,
		}

		// Convert severity string to types.Severity if present
		if vulnInfo.Severity != "" {
			severity, err := types.NewSeverity(strings.ToUpper(vulnInfo.Severity))
			if err == nil {
				adv.Severity = severity
			}
		}

		// See https://gitlab.alpinelinux.org/alpine/infra/docker/secdb/-/issues/3
		// e.g. CVE-2017-2616 (+ regression fix)
		ids := strings.Fields(cveID)
		for _, id := range ids {
			if err := vs.dbc.PutAdvisoryDetail(tx, id, pkgName, []string{distroName}, adv); err != nil {
				return oops.Wrapf(err, "failed to save advisory detail")
			}

			// for optimization
			if err := vs.dbc.PutVulnerabilityID(tx, id); err != nil {
				return oops.Wrapf(err, "failed to save the vulnerability ID")
			}
		}
	}
	return nil
}

func (vs VulnSrc) Get(pkgName string) ([]types.Advisory, error) {
	eb := oops.In(string(source.ID))

	advisories, err := vs.dbc.GetAdvisories(distroName, pkgName)
	if err != nil {
		return nil, eb.With("bucket", distroName).Wrapf(err, "failed to get advisories")
	}

	return advisories, nil
}
