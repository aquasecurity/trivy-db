package nvd

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"path/filepath"

	"github.com/aquasecurity/trivy-db/pkg/types"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	nvdDir = "nvd"
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
	rootDir := filepath.Join(dir, "vuln-list", nvdDir)

	var items []Item
	buffer := &bytes.Buffer{}
	err := utils.FileWalk(rootDir, func(r io.Reader, _ string) error {
		item := Item{}
		if _, err := buffer.ReadFrom(r); err != nil {
			return xerrors.Errorf("failed to read file: %w", err)
		}
		if err := json.Unmarshal(buffer.Bytes(), &item); err != nil {
			return xerrors.Errorf("failed to decode NVD JSON: %w", err)
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

func (vs VulnSrc) commit(tx *bolt.Tx, items []Item) error {
	for _, item := range items {
		cveID := item.Cve.Meta.ID
		severity, _ := types.NewSeverity(item.Impact.BaseMetricV2.Severity)
		severityV3, _ := types.NewSeverity(item.Impact.BaseMetricV3.CvssV3.BaseSeverity)

		var references []string
		for _, ref := range item.Cve.References.ReferenceDataList {
			references = append(references, ref.URL)
		}

		var description string
		for _, d := range item.Cve.Description.DescriptionDataList {
			if d.Value != "" {
				description = d.Value
				break
			}
		}

		vuln := types.VulnerabilityDetail{
			CvssScore:    item.Impact.BaseMetricV2.CvssV2.BaseScore,
			CvssVector:   item.Impact.BaseMetricV2.CvssV2.VectorString,
			CvssScoreV3:  item.Impact.BaseMetricV3.CvssV3.BaseScore,
			CvssVectorV3: item.Impact.BaseMetricV3.CvssV3.VectorString,
			Severity:     severity,
			SeverityV3:   severityV3,
			References:   references,
			Title:        "",
			Description:  description,
		}

		if err := vs.dbc.PutVulnerabilityDetail(tx, cveID, vulnerability.Nvd, vuln); err != nil {
			return err
		}
	}
	return nil
}

func (vs VulnSrc) save(items []Item) error {
	log.Println("NVD batch update")
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, items)
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}
	return nil
}
