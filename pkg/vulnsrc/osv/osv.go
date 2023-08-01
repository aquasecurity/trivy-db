package osv

import (
	"encoding/json"
	"fmt"
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
	sourceID   = vulnerability.OSV
)

var ecosystems = []ecosystem{
	{
		dir:  "python",
		name: vulnerability.Pip,
		dataSource: types.DataSource{
			ID:   sourceID,
			Name: "Python Packaging Advisory Database",
			URL:  "https://github.com/pypa/advisory-db",
		},
	},
	// Cargo ecosystem advisories in OSV were disabled,
	// because GitHub Advisory Database contains almost all information.
	/*
		{
			dir:  "rust",
			name: vulnerability.Cargo,
			dataSource: types.DataSource{
				ID:   sourceID,
				Name: "RustSec Advisory Database",
				URL:  "https://github.com/RustSec/advisory-db",
			},
		},
	*/

	// Go ecosystem advisories in OSV were disabled,
	// because GitHub Advisory Database contains almost all information.
	//{dir: "go", pkgType: vulnerability.Go, sourceID: vulnerability.OSVGo},
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
	return sourceID
}

func (vs VulnSrc) Update(dir string) error {
	for _, eco := range ecosystems {
		log.Printf("    Updating Open Source Vulnerability %s", eco.name)
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
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		for _, entry := range entries {
			if err := vs.commit(tx, eco, entry); err != nil {
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

func (vs VulnSrc) commit(tx *bolt.Tx, eco ecosystem, entry Entry) error {

	if entry.Withdrawn != nil && entry.Withdrawn.Before(time.Now()) {
		return nil
	}

	bktName := bucket.Name(string(eco.name), dataSource)

	if err := vs.dbc.PutDataSource(tx, bktName, eco.dataSource); err != nil {
		return xerrors.Errorf("failed to put data source: %w", err)
	}

	// Aliases contain CVE-IDs
	vulnIDs := filterCveIDs(entry.Aliases)
	if len(vulnIDs) == 0 {
		// e.g. PYSEC-2021-335
		vulnIDs = []string{entry.ID}
	}

	var references []string
	for _, ref := range entry.References {
		references = append(references, ref.URL)
	}

	for _, affected := range entry.Affected {
		pkgName := vulnerability.NormalizePkgName(eco.name, affected.Package.Name)
		var patchedVersions, vulnerableVersions, unaffectedVersions []string
		for _, affects := range affected.Ranges {
			if affects.Type == RangeTypeGit {
				continue
			}

			var vulnerable string
			for _, event := range affects.Events {
				switch {
				case event.Introduced != "":
					// e.g. {"introduced": "1.2.0}, {"introduced": "2.2.0}
					if vulnerable != "" {
						vulnerableVersions = append(vulnerableVersions, vulnerable)
					}
					vulnerable = fmt.Sprintf(">=%s", event.Introduced)
				case event.Fixed != "":
					// patched versions
					patchedVersions = append(patchedVersions, event.Fixed)

					// e.g. {"introduced": "1.2.0}, {"fixed": "1.2.5}
					vulnerable = fmt.Sprintf("%s, <%s", vulnerable, event.Fixed)
				case event.LastAffected != "":
					unaffectedVersions = append(unaffectedVersions, fmt.Sprintf(">%s", event.LastAffected))
					vulnerable = fmt.Sprintf("%s, <=%s", vulnerable, event.LastAffected)
				}
			}
			if vulnerable != "" {
				vulnerableVersions = append(vulnerableVersions, vulnerable)
			}
		}

		advisory := types.Advisory{
			VulnerableVersions: vulnerableVersions,
			PatchedVersions:    patchedVersions,
			UnaffectedVersions: unaffectedVersions,
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

		if err := vs.dbc.PutVulnerabilityDetail(tx, vulnID, sourceID, vuln); err != nil {
			return xerrors.Errorf("failed to put vulnerability detail (%s): %w", vulnID, err)
		}

		if err := vs.dbc.PutVulnerabilityID(tx, vulnID); err != nil {
			return xerrors.Errorf("failed to put vulnerability id (%s): %w", vulnID, err)
		}
	}
	return nil
}

func filterCveIDs(aliases []string) []string {
	var cveIDs []string
	for _, a := range aliases {
		if strings.HasPrefix(a, "CVE-") {
			cveIDs = append(cveIDs, a)
		}
	}
	return cveIDs
}
