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
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	golvulnDBDir = "go"
)

type VulnSrc struct {
	dbc db.Operation
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", golvulnDBDir)

	var items []Entry
	buffer := &bytes.Buffer{}
	err := utils.FileWalk(rootDir, func(r io.Reader, _ string) error {
		item := Entry{}
		if _, err := buffer.ReadFrom(r); err != nil {
			return xerrors.Errorf("failed to read file: %w", err)
		}
		if err := json.Unmarshal(buffer.Bytes(), &item); err != nil {
			return xerrors.Errorf("failed to decode go-vulndb JSON: %w", err)
		}
		buffer.Reset()
		items = append(items, item)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in NVD walk: %w", err)
	}

	if err = vs.save(items); err != nil {
		return xerrors.Errorf("error in NVD save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(items []Entry) error {
	log.Println("go-vulndb batch update")
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, items)
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, items []Entry) error {
	for _, item := range items {
		cveID := item.ID
		var patchedVersions []string
		for _, fixedVersions := range item.Affects.Ranges {
			patchedVersions = append(patchedVersions, fixedVersions.Fixed)
		}
		a := types.Advisory{
			VulnerabilityID: cveID,
			PatchedVersions: patchedVersions,
		}
		err := vs.dbc.PutAdvisoryDetail(tx, cveID, vulnerability.GoVulnDB, item.Package.Name, a)
		if err != nil {
			return xerrors.Errorf("failed to save go-vulndb advisory: %w", err)
		}
		var references []string
		for _, ref := range item.References {
			references = append(references, ref.URL)
		}
		if item.Extra.Go.URL != "" {
			references = append(references, item.Extra.Go.URL)
		}
		vuln := types.VulnerabilityDetail{
			ID:               cveID,
			Title:            fmt.Sprintf("vulnerability in package %v", item.Package.Name),
			Description:      item.Details,
			References:       references,
			PublishedDate:    &item.Published,
			LastModifiedDate: &item.Modified,
		}
		if err := vs.dbc.PutVulnerabilityDetail(tx, cveID, vulnerability.GoVulnDB, vuln); err != nil {
			return err
		}
		if err := vs.dbc.PutSeverity(tx, cveID, types.SeverityUnknown); err != nil {
			return xerrors.Errorf("failed to save go-vulndb vulnerability severity: %w", err)
		}
	}
	return nil
}
