package bottlerocket

import (
	"encoding/json"
	"io"
	"path/filepath"
	"strings"

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
		URL:  "https://advisories.bottlerocket.aws/updateinfo.xml.gz",
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
	rootDir := filepath.Join(dir, "vuln-list", bottlerocketDir)
	eb := oops.In("bottlerocket").With("root_dir", rootDir)

	var advisories []Advisory
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var adv Advisory
		if err := json.NewDecoder(r).Decode(&adv); err != nil {
			return eb.With("file_path", path).Wrapf(err, "json decode error")
		}
		advisories = append(advisories, adv)
		return nil
	})
	if err != nil {
		return eb.Wrapf(err, "walk error")
	}

	if err = vs.save(advisories); err != nil {
		return eb.Wrapf(err, "save error")
	}

	return nil
}

func (vs VulnSrc) save(advisories []Advisory) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, advisories)
	})
	if err != nil {
		return oops.Wrapf(err, "batch update error")
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, advisories []Advisory) error {
	if err := vs.dbc.PutDataSource(tx, platformName, source); err != nil {
		return oops.Wrapf(err, "failed to put data source")
	}

	for _, adv := range advisories {
		// Prefer the CVE IDs from the advisory references, but fall back to other
		// reference IDs (e.g. GHSA/BRSA) for advisories that have no CVE assigned,
		// so they are still recorded.
		var vulnIDs, fallbackIDs []string
		var references []string
		for _, ref := range adv.References {
			if ref.Type == "cve" {
				vulnIDs = append(vulnIDs, ref.ID)
			} else {
				fallbackIDs = append(fallbackIDs, ref.ID)
			}
			references = append(references, ref.Href)
		}
		if len(vulnIDs) == 0 {
			vulnIDs = fallbackIDs
		}

		vuln := types.VulnerabilityDetail{
			Severity:    convertSeverity(adv.Severity),
			References:  references,
			Description: adv.Description,
			Title:       adv.Title,
		}

		for _, vulnID := range vulnIDs {
			for _, pkg := range adv.Packages {
				advisory := types.Advisory{
					FixedVersion: utils.ConstructVersion(pkg.Epoch, pkg.Version, pkg.Release),
				}
				if err := vs.dbc.PutAdvisoryDetail(tx, vulnID, pkg.Name, []string{platformName}, advisory); err != nil {
					return oops.Wrapf(err, "failed to save advisory")
				}
			}

			if err := vs.dbc.PutVulnerabilityDetail(tx, vulnID, source.ID, vuln); err != nil {
				return oops.Wrapf(err, "failed to save vulnerability detail")
			}

			if err := vs.dbc.PutVulnerabilityID(tx, vulnID); err != nil {
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

func convertSeverity(severity string) types.Severity {
	switch strings.ToLower(severity) {
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
