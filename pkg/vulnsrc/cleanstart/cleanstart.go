package cleanstart

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

const cleanstartDir = "cleanstart"

var (
	platformName = bucket.NewCleanStart("").Name()
	source       = types.DataSource{
		ID:   vulnerability.CleanStart,
		Name: "CleanStart Security Advisories",
		URL:  "https://github.com/cleanstart-dev/cleanstart-security-advisories",
	}
)

// OSV advisory format
type osvAdvisory struct {
	ID       string        `json:"id"`
	Affected []osvAffected `json:"affected"`
	Upstream []string      `json:"upstream"`
}

type osvAffected struct {
	Package osvPackage  `json:"package"`
	Ranges  []osvRange  `json:"ranges"`
}

type osvPackage struct {
	Name string `json:"name"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
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
	// advisories are stored under advisories/YYYY/*.json
	rootDir := filepath.Join(dir, cleanstartDir)
	eb := oops.In(string(source.ID)).With("root_dir", rootDir)

	var advisories []osvAdvisory
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var adv osvAdvisory
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

func (vs VulnSrc) save(advisories []osvAdvisory) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		if err := vs.dbc.PutDataSource(tx, platformName, source); err != nil {
			return oops.Wrapf(err, "failed to put data source")
		}
		for _, adv := range advisories {
			if err := vs.saveAdvisory(tx, adv); err != nil {
				return oops.Wrapf(err, "failed to save advisory %s", adv.ID)
			}
		}
		return nil
	})
	if err != nil {
		return oops.Wrapf(err, "batch update failed")
	}
	return nil
}

func (vs VulnSrc) saveAdvisory(tx *bolt.Tx, adv osvAdvisory) error {
	for _, affected := range adv.Affected {
		pkgName := affected.Package.Name
		fixedVersion := extractFixedVersion(affected.Ranges)
		if fixedVersion == "" {
			continue
		}

		advisory := types.Advisory{
			FixedVersion: fixedVersion,
		}

		// Store once per upstream CVE so Trivy can match against NVD data
		for _, cveID := range adv.Upstream {
			if err := vs.dbc.PutAdvisoryDetail(tx, cveID, pkgName, []string{platformName}, advisory); err != nil {
				return oops.Wrapf(err, "failed to save advisory detail for %s", cveID)
			}
			if err := vs.dbc.PutVulnerabilityID(tx, cveID); err != nil {
				return oops.Wrapf(err, "failed to save vulnerability ID %s", cveID)
			}
		}

		// Also store under the CleanStart advisory ID itself
		if err := vs.dbc.PutAdvisoryDetail(tx, adv.ID, pkgName, []string{platformName}, advisory); err != nil {
			return oops.Wrapf(err, "failed to save advisory detail for %s", adv.ID)
		}
		if err := vs.dbc.PutVulnerabilityID(tx, adv.ID); err != nil {
			return oops.Wrapf(err, "failed to save vulnerability ID %s", adv.ID)
		}
	}
	return nil
}

func extractFixedVersion(ranges []osvRange) string {
	for _, r := range ranges {
		if r.Type != "ECOSYSTEM" {
			continue
		}
		for _, event := range r.Events {
			if event.Fixed != "" {
				return event.Fixed
			}
		}
	}
	return ""
}

func (vs VulnSrc) Get(params db.GetParams) ([]types.Advisory, error) {
	eb := oops.In(string(source.ID))
	advisories, err := vs.dbc.GetAdvisories(platformName, params.PkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get advisories")
	}
	return advisories, nil
}