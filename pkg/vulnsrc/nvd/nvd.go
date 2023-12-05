package nvd

import (
	"bytes"
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
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	vulnListDir = "vuln-list-nvd"
	apiDir      = "api"
	primaryType = "Primary" // NVD has 2 type enums: `Primary` and `Secondary`
)

type VulnSrc struct {
	dbc db.Operation
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Name() types.SourceID {
	return vulnerability.NVD
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, vulnListDir, apiDir)

	var cves []Cve
	buffer := &bytes.Buffer{}
	err := utils.FileWalk(rootDir, func(r io.Reader, _ string) error {
		cve := Cve{}
		if _, err := buffer.ReadFrom(r); err != nil {
			return xerrors.Errorf("failed to read file: %w", err)
		}
		if err := json.Unmarshal(buffer.Bytes(), &cve); err != nil {
			return xerrors.Errorf("failed to decode NVD JSON: %w", err)
		}
		buffer.Reset()
		cves = append(cves, cve)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in NVD walk: %w", err)
	}

	if err = vs.save(cves); err != nil {
		return xerrors.Errorf("error in NVD save: %w", err)
	}

	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, cves []Cve) error {
	for _, cve := range cves {
		cveID := cve.ID

		var cvssScore, cvssScoreV3 float64
		var cvssVector, CvssVectorV3 string
		var severity, severityV3 types.Severity
		for _, metricV2 := range cve.Metrics.CvssMetricV2 {
			if metricV2.CvssData.BaseScore != 0 && metricV2.CvssData.VectorString != "" && metricV2.BaseSeverity != "" {
				cvssScore = metricV2.CvssData.BaseScore
				cvssVector = metricV2.CvssData.VectorString
				severity, _ = types.NewSeverity(metricV2.BaseSeverity)
				if metricV2.Type == primaryType {
					break
				}
			}
		}
		for _, metricV31 := range cve.Metrics.CvssMetricV31 {
			if metricV31.CvssData.BaseScore != 0 && metricV31.CvssData.VectorString != "" && metricV31.CvssData.BaseSeverity != "" {
				cvssScoreV3 = metricV31.CvssData.BaseScore
				CvssVectorV3 = metricV31.CvssData.VectorString
				severityV3, _ = types.NewSeverity(metricV31.CvssData.BaseSeverity)
				if metricV31.Type == primaryType {
					break
				}
			}
		}

		var references []string
		for _, ref := range cve.References {
			references = append(references, ref.URL)
		}

		var description string
		for _, d := range cve.Descriptions {
			if d.Value != "" {
				description = d.Value
				break
			}
		}
		var cweIDs []string
		for _, data := range cve.Weaknesses {
			for _, desc := range data.Description {
				if !strings.HasPrefix(desc.Value, "CWE") || data.Type != primaryType {
					continue
				}
				cweIDs = append(cweIDs, desc.Value)
			}
		}

		publishedDate, _ := time.Parse("2006-01-02T15:04:05", cve.Published)
		lastModifiedDate, _ := time.Parse("2006-01-02T15:04:05", cve.LastModified)

		vuln := types.VulnerabilityDetail{
			CvssScore:        cvssScore,
			CvssVector:       cvssVector,
			CvssScoreV3:      cvssScoreV3,
			CvssVectorV3:     CvssVectorV3,
			Severity:         severity,
			SeverityV3:       severityV3,
			CweIDs:           cweIDs,
			References:       references,
			Title:            "",
			Description:      description,
			PublishedDate:    &publishedDate,
			LastModifiedDate: &lastModifiedDate,
		}

		if err := vs.dbc.PutVulnerabilityDetail(tx, cveID, vulnerability.NVD, vuln); err != nil {
			return err
		}
	}
	return nil
}

func (vs VulnSrc) save(cves []Cve) error {
	log.Println("NVD batch update")
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, cves)
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}
	return nil
}
