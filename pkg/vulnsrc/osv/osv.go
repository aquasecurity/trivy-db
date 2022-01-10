package osv

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"

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
	{dir: "python", pkgType: vulnerability.Pip, source: vulnerability.OSVPyPI},
	{dir: "rust", pkgType: vulnerability.Cargo, source: vulnerability.OSVCratesio},

	// We cannot use OSV for golang scanning until module names are included.
	// See https://github.com/golang/go/issues/50006 for the detail.
	//{dir: "go", pkgType: vulnerability.Go, source: vulnerability.OSVGo},
}

type ecosystem struct {
	dir     string
	pkgType string
	source  string
}

type VulnSrc struct {
	dbc db.Operation
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Name() string {
	return "osv"
}

func (vs VulnSrc) Update(dir string) error {
	for _, eco := range ecosystems {
		log.Printf("    Updating Open Source Vulnerability %s", eco.pkgType)
		rootDir := filepath.Join(dir, "vuln-list", osvDir, eco.dir)

		var entries []OSV
		err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
			var osv OSV
			if err := json.NewDecoder(r).Decode(&osv); err != nil {
				return xerrors.Errorf("JSON decode error (%s): %w", path, err)
			}
			entries = append(entries, osv)
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

func (vs VulnSrc) save(eco ecosystem, entries []OSV) error {
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

func (vs VulnSrc) commit(tx *bolt.Tx, eco ecosystem, entry OSV) error {
	bktName, err := bucket.Name(eco.pkgType, dataSource)
	if err != nil {
		return xerrors.Errorf("bucket error: %w", err)
	}

	// Aliases contain CVE-IDs
	vulnIDs := filterCveIDs(entry.Aliases)
	if len(vulnIDs) == 0 {
		// e.g. PYSEC-2021-335
		vulnIDs = []string{entry.ID}
	}

	var references []string
	for _, ref := range entry.References {
		references = append(references, ref.Url)
	}

	for _, affected := range entry.Affected {

		var patchedVersions, vulnerableVersions []string
		for _, affects := range affected.Ranges {
			if affects.Type == "GIT" {
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
				}
			}
			if vulnerable != "" {
				vulnerableVersions = append(vulnerableVersions, vulnerable)
			}
		}

		advisory := types.Advisory{
			VulnerableVersions: vulnerableVersions,
			PatchedVersions:    patchedVersions,
		}

		for _, vulnID := range vulnIDs {
			if err = vs.dbc.PutAdvisoryDetail(tx, vulnID, bktName, affected.Package.Name, advisory); err != nil {
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

		if err = vs.dbc.PutVulnerabilityDetail(tx, vulnID, eco.source, vuln); err != nil {
			return xerrors.Errorf("failed to put vulnerability detail (%s): %w", vulnID, err)
		}

		if err = vs.dbc.PutVulnerabilityID(tx, vulnID); err != nil {
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
