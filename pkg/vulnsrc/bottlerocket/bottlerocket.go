package bottlerocket

import (
	"encoding/json"
	"io"
	"path/filepath"

	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const bottlerocketDir = "bottlerocket"

var (
	platformName = bucket.NewBottlerocket().Name()
	source       = types.DataSource{
		ID:   vulnerability.Bottlerocket,
		Name: "Bottlerocket Security Advisories",
		URL:  "https://advisories.bottlerocket.aws/",
	}
)

type VulnSrc struct {
	dbc        db.Operation
	advisories []Advisory
}

type Advisory struct {
	ID          string      `json:"id,omitempty"`
	Title       string      `json:"title,omitempty"`
	Severity    string      `json:"severity,omitempty"`
	Description string      `json:"description,omitempty"`
	Packages    []Package   `json:"packages,omitempty"`
	References  []Reference `json:"references,omitempty"`
	CveIDs      []string    `json:"cveids,omitempty"`
}

type Package struct {
	Name    string `json:"name,omitempty"`
	Epoch   string `json:"epoch,omitempty"`
	Version string `json:"version,omitempty"`
	Release string `json:"release,omitempty"`
	Arch    string `json:"arch,omitempty"`
}

type Reference struct {
	Href string `json:"href,omitempty"`
	ID   string `json:"id,omitempty"`
	Type string `json:"type,omitempty"`
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
	rootDir := filepath.Join(dir, "vuln-list", bottlerocketDir)
	eb := oops.In("bottlerocket").With("root_dir", rootDir)

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
	var adv Advisory
	if err := json.NewDecoder(r).Decode(&adv); err != nil {
		return oops.With("file_path", path).Wrapf(err, "json decode error")
	}
	vs.advisories = append(vs.advisories, adv)
	return nil
}

func (vs VulnSrc) save() error {
	err := vs.dbc.BatchUpdate(vs.commit)
	if err != nil {
		return oops.Wrapf(err, "batch update error")
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx) error {
	if err := vs.dbc.PutDataSource(tx, platformName, source); err != nil {
		return oops.Wrapf(err, "failed to put data source")
	}

	for _, adv := range vs.advisories {
		for _, cveID := range adv.CveIDs {
			for _, pkg := range adv.Packages {
				advisory := types.Advisory{
					FixedVersion: utils.ConstructVersion(pkg.Epoch, pkg.Version, pkg.Release),
				}
				if err := vs.dbc.PutAdvisoryDetail(tx, cveID, pkg.Name, []string{platformName}, advisory); err != nil {
					return oops.Wrapf(err, "failed to save advisory")
				}
			}

			var references []string
			for _, ref := range adv.References {
				references = append(references, ref.Href)
			}

			vuln := types.VulnerabilityDetail{
				Severity:    severityFromPriority(adv.Severity),
				References:  references,
				Description: adv.Description,
				Title:       adv.Title,
			}
			if err := vs.dbc.PutVulnerabilityDetail(tx, cveID, source.ID, vuln); err != nil {
				return oops.Wrapf(err, "failed to save vulnerability detail")
			}

			if err := vs.dbc.PutVulnerabilityID(tx, cveID); err != nil {
				return oops.Wrapf(err, "failed to save vulnerability ID")
			}
		}
	}
	return nil
}

func (vs VulnSrc) Get(params db.GetParams) ([]types.Advisory, error) {
	eb := oops.In("bottlerocket")
	advisories, err := vs.dbc.GetAdvisories(platformName, params.PkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get advisories")
	}
	return advisories, nil
}

func severityFromPriority(priority string) types.Severity {
	switch priority {
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
