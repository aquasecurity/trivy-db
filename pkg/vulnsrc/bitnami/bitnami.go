package bitnami

import (
	"encoding/json"
	"io"
	"log"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/osv"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	bitnamiDir = "bitnami-vulndb"
)

var bucketName = bucket.Name(string(vulnerability.Bitnami), string(vulnerability.BitnamiVulndb))

type VulnSrc struct {
	dbc db.Operation
}

var source = types.DataSource{
	ID:   vulnerability.BitnamiVulndb,
	Name: "Bitnami Vulnerability Database",
	URL:  "https://github.com/bitnami/vulndb",
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
	log.Println("Updating Bitnami DB...")

	rootDir := filepath.Join(dir, bitnamiDir, "data")
	var entries []osv.Entry
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var entry osv.Entry
		if err := json.NewDecoder(r).Decode(&entry); err != nil {
			return xerrors.Errorf("JSON decode error (%s): %w", path, err)
		}

		entries = append(entries, entry)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("walk error: %w", err)
	}

	if err = vs.save(entries); err != nil {
		return xerrors.Errorf("save error: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(entries []osv.Entry) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		if err := vs.dbc.PutDataSource(tx, bucketName, source); err != nil {
			return xerrors.Errorf("failed to put data source: %w", err)
		}

		for _, entry := range entries {
			if err := vs.commit(tx, entry); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return xerrors.Errorf("batch update error: %w", err)
	}

	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, entry osv.Entry) error {
	if entry.Withdrawn != nil && entry.Withdrawn.Before(time.Now()) {
		return nil
	}

	// Aliases contain CVE-IDs
	vulnIDs := osv.FilterCveIDs(entry.Aliases)
	if len(vulnIDs) == 0 {
		vulnIDs = []string{entry.ID}
	}

	var references []string
	for _, ref := range entry.References {
		references = append(references, ref.URL)
	}

	for _, affected := range entry.Affected {
		pkgName := vulnerability.NormalizePkgName(vulnerability.Bitnami, affected.Package.Name)
		var advisory types.Advisory
		if len(affected.Ranges) > 0 || len(affected.Versions) > 0 {
			advisory = osv.GetAdvisory(affected)
		}

		for _, vulnID := range vulnIDs {
			if err := vs.dbc.PutAdvisoryDetail(tx, vulnID, pkgName, []string{bucketName}, advisory); err != nil {
				return xerrors.Errorf("failed to save OSV advisory: %w", err)
			}
		}
	}

	for _, vulnID := range vulnIDs {
		vuln := types.VulnerabilityDetail{
			Title:       entry.Summary,
			Description: entry.Details,
			References:  references,
		}

		if err := vs.dbc.PutVulnerabilityDetail(tx, vulnID, vulnerability.BitnamiVulndb, vuln); err != nil {
			return xerrors.Errorf("failed to put vulnerability detail (%s): %w", vulnID, err)
		}

		if err := vs.dbc.PutVulnerabilityID(tx, vulnID); err != nil {
			return xerrors.Errorf("failed to put vulnerability id (%s): %w", vulnID, err)
		}
	}

	return nil
}

func (vs VulnSrc) Get(_, pkgName string) ([]types.Advisory, error) {
	advisories, err := vs.dbc.GetAdvisories(bucketName, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get Bitnami advisories: %w", err)
	}
	return advisories, nil
}
