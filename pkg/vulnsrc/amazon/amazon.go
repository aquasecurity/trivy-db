package amazon

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	amazonDir      = "amazon"
	platformFormat = "amazon linux %s"
)

var (
	targetVersions = []string{"1", "2", "2022", "2023"}

	source = types.DataSource{
		ID:   vulnerability.Amazon,
		Name: "Amazon Linux Security Center",
		URL:  "https://alas.aws.amazon.com/",
	}
)

type VulnSrc struct {
	dbc        db.Operation
	logger     *log.Logger
	advisories map[string][]ALAS
}

// ALAS has detailed data of ALAS
type ALAS struct {
	ID          string      `json:"id,omitempty"`
	Title       string      `json:"title,omitempty"`
	Severity    string      `json:"severity,omitempty"`
	Description string      `json:"description,omitempty"`
	Packages    []Package   `json:"packages,omitempty"`
	References  []Reference `json:"references,omitempty"`
	CveIDs      []string    `json:"cveids,omitempty"`
}

// Package has affected package information
type Package struct {
	Name    string `json:"name,omitempty"`
	Epoch   string `json:"epoch,omitempty"`
	Version string `json:"version,omitempty"`
	Release string `json:"release,omitempty"`
	Arch    string `json:"arch,omitempty"`
}

// Reference has reference information
type Reference struct {
	Href string `json:"href,omitempty"`
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc:        db.Config{},
		logger:     log.WithPrefix("amazon"),
		advisories: map[string][]ALAS{},
	}
}

func (vs VulnSrc) Name() types.SourceID {
	return source.ID
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", amazonDir)
	eb := oops.In("amazon").With("root_dir", rootDir)

	err := utils.FileWalk(rootDir, vs.walkFunc)
	if err != nil {
		return eb.Wrapf(err, "walk error")
	}

	if err = vs.save(); err != nil {
		return eb.Wrapf(err, "save error")
	}

	return nil
}

func (vs *VulnSrc) walkFunc(r io.Reader, path string) error {
	paths := strings.Split(path, string(filepath.Separator))
	if len(paths) < 2 {
		return nil
	}
	version := paths[len(paths)-2]
	if !slices.Contains(targetVersions, version) {
		vs.logger.Warn("Unsupported Amazon version", "version", version)
		return nil
	}

	var alas ALAS
	if err := json.NewDecoder(r).Decode(&alas); err != nil {
		return oops.With("file_path", path).With("version", version).Wrapf(err, "json decode error")
	}

	vs.advisories[version] = append(vs.advisories[version], alas)
	return nil
}

func (vs VulnSrc) save() error {
	vs.logger.Info("Saving DB")
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx)
	})
	if err != nil {
		return oops.Wrapf(err, "batch update error")
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx) error {
	for majorVersion, alasList := range vs.advisories {
		platformName := fmt.Sprintf(platformFormat, majorVersion)

		if err := vs.dbc.PutDataSource(tx, platformName, source); err != nil {
			return oops.Wrapf(err, "failed to put data source")
		}
		for _, alas := range alasList {
			for _, cveID := range alas.CveIDs {
				for _, pkg := range alas.Packages {
					advisory := types.Advisory{
						FixedVersion: utils.ConstructVersion(pkg.Epoch, pkg.Version, pkg.Release),
					}
					if err := vs.dbc.PutAdvisoryDetail(tx, cveID, pkg.Name, []string{platformName}, advisory); err != nil {
						return oops.Wrapf(err, "failed to save advisory")
					}

				}
				var references []string
				for _, ref := range alas.References {
					references = append(references, ref.Href)
				}

				vuln := types.VulnerabilityDetail{
					Severity:    severityFromPriority(alas.Severity),
					References:  references,
					Description: alas.Description,
					Title:       "",
				}
				if err := vs.dbc.PutVulnerabilityDetail(tx, cveID, source.ID, vuln); err != nil {
					return oops.Wrapf(err, "failed to save vulnerability detail")
				}

				// for optimization
				if err := vs.dbc.PutVulnerabilityID(tx, cveID); err != nil {
					return oops.Wrapf(err, "failed to save vulnerability ID")
				}
			}
		}
	}
	return nil
}

// Get returns a security advisory
func (vs VulnSrc) Get(version string, pkgName string) ([]types.Advisory, error) {
	eb := oops.In("amazon").With("version", version)
	bucket := fmt.Sprintf(platformFormat, version)
	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get advisories")
	}
	return advisories, nil
}

func severityFromPriority(priority string) types.Severity {
	switch strings.ToLower(priority) {
	case "low":
		return types.SeverityLow
	case "medium":
		return types.SeverityMedium
	case "important":
		return types.SeverityHigh
	case "critical":
		return types.SeverityCritical
	default:
		return types.SeverityUnknown
	}
}
