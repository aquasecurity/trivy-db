package govulndb

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/vuln/osv"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/overridedb"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const govulndbDir = "go"

var (
	source = types.DataSource{
		ID:   vulnerability.GoVulnDB,
		Name: "The Go Vulnerability Database",
		URL:  "https://github.com/golang/vulndb",
	}

	bucketName = bucket.Name(string(vulnerability.Go), source.Name)
)

type VulnSrc struct {
	dbc          db.Operation
	overriddenDb *overridedb.OverriddenData
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Name() types.SourceID {
	return source.ID
}

func (vs VulnSrc) Update(dir string, db *overridedb.OverriddenData) error {
	rootDir := filepath.Join(dir, "vuln-list", govulndbDir)

	var items []Entry
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var item Entry
		if err := json.NewDecoder(r).Decode(&item); err != nil {
			return xerrors.Errorf("JSON decode error (%s): %w", path, err)
		}

		// Standard libraries are not listed in go.sum, etc.
		if item.Module == "stdlib" {
			return nil
		}
		items = append(items, item)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("walk error: %w", err)
	}

	if err = vs.save(items); err != nil {
		return xerrors.Errorf("save error: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(items []Entry) error {
	log.Println("Saving The Go Vulnerability Database")
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		if err := vs.dbc.PutDataSource(tx, bucketName, source); err != nil {
			return xerrors.Errorf("failed to put data source: %w", err)
		}

		for _, item := range items {
			if err := vs.commit(tx, item); err != nil {
				return xerrors.Errorf("commit error (%s): %w", item.ID, err)
			}
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("batch update error: %w", err)
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, item Entry) error {
	// Aliases contain CVE-IDs
	vulnIDs := getVulnIDs(item.ID, item.Aliases)

	// Take a single affected entry
	affected := findAffected(item.Module, item.Affected)
	if len(affected.Ranges) == 0 {
		return xerrors.Errorf("invalid entry: %s %s", item.ID, item.Module)
	}

	var patchedVersions, vulnerableVersions, references []string
	for _, affects := range affected.Ranges {
		var vulnerable string
		for _, event := range affects.Events {
			switch {
			case event.Introduced != "":
				// e.g. {"introduced": "1.2.0}, {"introduced": "2.2.0}
				if vulnerable != "" {
					vulnerableVersions = append(vulnerableVersions, vulnerable)
				}
				if event.Introduced == "0" {
					event.Introduced = "0.0.0-0"
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

	if affected.DatabaseSpecific.URL != "" {
		references = append(references, affected.DatabaseSpecific.URL)
	}

	// Update references
	for _, ref := range item.References {
		references = append(references, ref.URL)
	}

	a := types.Advisory{
		PatchedVersions:    patchedVersions,
		VulnerableVersions: vulnerableVersions,
	}

	// A module name must be filled.
	pkgName := item.Module

	for _, vulnID := range vulnIDs {
		err := vs.dbc.PutAdvisoryDetail(tx, vulnID, pkgName, []string{bucketName}, a)
		if err != nil {
			return xerrors.Errorf("failed to save go-vulndb advisory: %w", err)
		}

		vuln := types.VulnerabilityDetail{
			Description: item.Details,
			References:  references,
		}
		if err = vs.dbc.PutVulnerabilityDetail(tx, vulnID, source.ID, vuln); err != nil {
			return xerrors.Errorf("failed to put vulnerability detail (%s): %w", vulnID, err)
		}

		// for optimization
		if err = vs.dbc.PutVulnerabilityID(tx, vulnID); err != nil {
			return xerrors.Errorf("failed to save the vulnerability ID: %w", err)
		}
	}

	return nil
}

func getVulnIDs(id string, aliases []string) []string {
	if len(aliases) == 0 {
		return []string{id}
	}
	var cveIDs []string
	for _, alias := range aliases {
		// if aliases contain both CVE-ID and GHSA-ID, we should save only CVE-ID
		// because GHSA-IDs is duplicates of CVE-IDs in this case
		if strings.HasPrefix(alias, "CVE") {
			cveIDs = append(cveIDs, alias)
		}
	}
	// aliases contain only GHSA-IDs
	if len(cveIDs) != 0 {
		return cveIDs
	}
	return aliases
}

func findAffected(module string, affectedList []osv.Affected) osv.Affected {
	// Multiple packages may be included in "affected".
	// We have to select the appropriate package matching the module name
	// because those packages may have different versioning.
	//
	// e.g. GO-2020-0017
	//   module   => github.com/dgrijalva/jwt-go/v4
	//   packages => github.com/dgrijalva/jwt-go and github.com/dgrijalva/jwt-go/v4
	//
	// We should ignore "github.com/dgrijalva/jwt-go" in the above case.
	for _, a := range affectedList {
		if a.Package.Name == module {
			return a
		}
	}

	// If there is no package that exactly matches the module name,
	// we'll choose a package that contains the module name.
	// e.g. GO-2021-0101
	//   module  => github.com/apache/thrift
	//   package => github.com/apache/thrift/lib/go/thrift
	for _, a := range affectedList {
		if strings.HasPrefix(a.Package.Name, module) {
			return a
		}
	}

	return osv.Affected{}
}
