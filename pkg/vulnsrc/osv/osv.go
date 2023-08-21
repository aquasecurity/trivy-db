package osv

import (
	"encoding/json"
	"io"
	"log"
	"path/filepath"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	osvDir     = "osv"
	dataSource = "Open Source Vulnerability"
)

var ecosystems = []ecosystem{
	{
		dir:  "python",
		name: vulnerability.Pip,
		dataSource: types.DataSource{
			ID:   vulnerability.OSV,
			Name: "Python Packaging Advisory Database",
			URL:  "https://github.com/pypa/advisory-db",
		},
	},
	// Cargo & Go ecosystem advisories in OSV were disabled,
	// because GitHub Advisory Database contains almost all information.
	/*
		{
			dir:  "rust",
			name: vulnerability.Cargo,
			dataSource: types.DataSource{
				ID:   vulnerability.OSV,
				Name: "RustSec Advisory Database",
				URL:  "https://github.com/RustSec/advisory-db",
			},
		},
		{
			dir:  "go",
			name: vulnerability.Go,
			dataSource: types.DataSource{
				ID:   vulnerability.OSV,
				Name: "Go Advisory Database",
				URL:  "https://pkg.go.dev/vuln",
			},
		},
	*/
}

type ecosystem struct {
	dir        string
	name       types.Ecosystem
	dataSource types.DataSource
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
	return vulnerability.OSV
}

func (vs VulnSrc) Update(dir string) error {
	for _, eco := range ecosystems {
		log.Printf("    Updating OSV - %s", eco.name)
		rootDir := filepath.Join(dir, "vuln-list", osvDir, eco.dir)

		var entries []Entry
		err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
			var entry Entry
			if err := json.NewDecoder(r).Decode(&entry); err != nil {
				return xerrors.Errorf("JSON decode error (%s): %w", path, err)
			}

			// GHSA-IDs are already stored via ghsa package.
			// Skip them to avoid duplication.
			if strings.HasPrefix(entry.ID, "GHSA") {
				return nil
			}

			entries = append(entries, entry)
			return nil
		})
		if err != nil {
			return xerrors.Errorf("walk error: %w", err)
		}

		if err = vs.save(eco, entries); err != nil {
			return xerrors.Errorf("save error: %w", err)
		}
	}

	return nil
}

func (vs VulnSrc) save(eco ecosystem, entries []Entry) error {
	bktName := bucket.Name(string(eco.name), dataSource)
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		if err := vs.dbc.PutDataSource(tx, bktName, eco.dataSource); err != nil {
			return xerrors.Errorf("failed to put data source: %w", err)
		}

		for _, entry := range entries {
			if err := vs.commit(tx, bktName, eco.name, entry); err != nil {
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

func (vs VulnSrc) commit(tx *bolt.Tx, bktName string, ecoName types.Ecosystem, entry Entry) error {
	if entry.Withdrawn != nil && entry.Withdrawn.Before(time.Now()) {
		return nil
	}

	// Aliases contain CVE-IDs
	vulnIDs := FilterCveIDs(entry.Aliases)
	if len(vulnIDs) == 0 {
		// e.g. PYSEC-2021-335
		vulnIDs = []string{entry.ID}
	}

	var references []string
	for _, ref := range entry.References {
		references = append(references, ref.URL)
	}

	for _, affected := range entry.Affected {
		pkgName := vulnerability.NormalizePkgName(ecoName, affected.Package.Name)
		var advisory types.Advisory
		if len(affected.Ranges) > 0 || len(affected.Versions) > 0 {
			advisory = GetAdvisory(affected)
		}

		for _, vulnID := range vulnIDs {
			if err := vs.dbc.PutAdvisoryDetail(tx, vulnID, pkgName, []string{bktName}, advisory); err != nil {
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

		if err := vs.dbc.PutVulnerabilityDetail(tx, vulnID, vulnerability.OSV, vuln); err != nil {
			return xerrors.Errorf("failed to put vulnerability detail (%s): %w", vulnID, err)
		}

		if err := vs.dbc.PutVulnerabilityID(tx, vulnID); err != nil {
			return xerrors.Errorf("failed to put vulnerability id (%s): %w", vulnID, err)
		}
	}
	return nil
}
