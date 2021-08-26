package govulndb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"

	bolt "go.etcd.io/bbolt"
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
	buffer := &bytes.Buffer{}
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		item := Entry{}
		if _, err := buffer.ReadFrom(r); err != nil {
			return xerrors.Errorf("failed to read file (%s): %w", path, err)
		}
		if err := json.Unmarshal(buffer.Bytes(), &item); err != nil {
			return xerrors.Errorf("JSON error (%s): %w", path, err)
		}
		buffer.Reset()
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

	var patchedVersions, vulnerableVersions []string
	for _, affect := range item.Affects.Ranges {
		// patched versions
		patchedVersions = append(patchedVersions, affect.Fixed)

		if affect.Fixed == "" {
			continue
		}

		// vulnerable versions
		vulnerable := fmt.Sprintf("< %s", affect.Fixed)
		if affect.Introduced != "" {
			vulnerable = fmt.Sprintf(">= %s, %s", affect.Introduced, vulnerable)
		}

		vulnerableVersions = append(vulnerableVersions, vulnerable)
	}

	a := types.Advisory{
		PatchedVersions:    patchedVersions,
		VulnerableVersions: vulnerableVersions,
	}

	pkgName := item.Module
	if pkgName == "" {
		pkgName = item.Package.Name
	}

	var references []string
	for _, ref := range item.References {
		references = append(references, ref.URL)
	}
	if item.EcosystemSpecific.URL != "" {
		references = append(references, item.EcosystemSpecific.URL)
	}

	prefixedBucketName, _ := bucket.Name(vulnerability.Go, bucketName)
	for _, vulnID := range vulnIDs {
		err := vs.dbc.PutAdvisoryDetail(tx, vulnID, prefixedBucketName, pkgName, a)
		if err != nil {
			return xerrors.Errorf("failed to save go-vulndb advisory: %w", err)
		}

		vuln := types.VulnerabilityDetail{
			ID:               vulnID,
			Description:      item.Details,
			References:       references,
			PublishedDate:    &item.Published,
			LastModifiedDate: &item.Modified,
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
