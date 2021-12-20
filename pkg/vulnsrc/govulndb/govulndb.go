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
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	govulndbDir = "go"
	bucketName  = "vulndb"
)

type VulnSrc struct {
	dbc db.Operation
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Name() string {
	return vulnerability.GoVulnDB
}

func (vs VulnSrc) Update(dir string) error {
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
	vulnIDs := item.Aliases
	if len(vulnIDs) == 0 {
		// e.g. GO-2021-0064
		vulnIDs = []string{item.ID}
	}

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

	prefixedBucketName, _ := bucket.Name(vulnerability.Go, bucketName)
	for _, vulnID := range vulnIDs {
		err := vs.dbc.PutAdvisoryDetail(tx, vulnID, prefixedBucketName, pkgName, a)
		if err != nil {
			return xerrors.Errorf("failed to save go-vulndb advisory: %w", err)
		}

		vuln := types.VulnerabilityDetail{
			Description: item.Details,
			References:  references,
		}
		if err = vs.dbc.PutVulnerabilityDetail(tx, vulnID, prefixedBucketName, vuln); err != nil {
			return xerrors.Errorf("failed to put vulnerability detail (%s): %w", vulnID, err)
		}

		if err = vs.dbc.PutSeverity(tx, vulnID, types.SeverityUnknown); err != nil {
			return xerrors.Errorf("failed to save go-vulndb vulnerability severity: %w", err)
		}
	}

	return nil
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
