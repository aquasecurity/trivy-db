package nvd

import (
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"time"

	gocvss40 "github.com/pandatix/go-cvss/40"
	"github.com/samber/lo"
	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	vulnListDir = "vuln-list-nvd"
	apiDir      = "api"
	nvdSource   = "nvd@nist.gov"
)

type DB interface {
	db.Operation
	Put(*bolt.Tx, Cve) error
}

type VulnSrc struct {
	DB
	logger *log.Logger
}

type NVD struct {
	db.Operation
}

func NewVulnSrc() *VulnSrc {
	return &VulnSrc{
		DB:     &NVD{Operation: db.Config{}},
		logger: log.WithPrefix("nvd"),
	}
}

func (vs *VulnSrc) Name() types.SourceID {
	return vulnerability.NVD
}

func (vs *VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, vulnListDir, apiDir)
	eb := oops.In("nvd").With("root_dir", rootDir)

	var cves []Cve
	buffer := &bytes.Buffer{}
	err := utils.FileWalk(rootDir, func(r io.Reader, filePath string) error {
		eb := eb.With("file_path", filePath)
		cve := Cve{}
		if _, err := buffer.ReadFrom(r); err != nil {
			return eb.Wrapf(err, "file read error")
		}
		if err := json.Unmarshal(buffer.Bytes(), &cve); err != nil {
			return eb.Wrapf(err, "json unmarshal error")
		}
		buffer.Reset()
		cves = append(cves, cve)
		return nil
	})
	if err != nil {
		return eb.Wrapf(err, "walk error")
	}

	if err = vs.save(cves); err != nil {
		return eb.Wrapf(err, "save error")
	}

	return nil
}

func (vs *VulnSrc) commit(tx *bolt.Tx, cves []Cve) error {
	for _, cve := range cves {
		if err := vs.Put(tx, cve); err != nil {
			return err
		}
	}
	return nil
}

func (vs *VulnSrc) save(cves []Cve) error {
	vs.logger.Info("NVD batch update")
	err := vs.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, cves)
	})
	if err != nil {
		return oops.Wrapf(err, "error in batch update")
	}
	return nil
}

// getCvssV2 selects vector, score and severity from V2 metrics
func getCvssV2(metricsV2 []CvssMetricV2) (score float64, vector string, severity types.Severity) {
	for _, metricV2 := range metricsV2 {
		// save only NVD metric
		if metricV2.Source == nvdSource {
			score = metricV2.CvssData.BaseScore
			vector = metricV2.CvssData.VectorString
			severity, _ = types.NewSeverity(metricV2.BaseSeverity)
			return
		}
	}
	return
}

// getCvssV3 selects vector, score and severity from V3* metrics
func getCvssV3(metricsV31, metricsV30 []CvssMetricV3) (score float64, vector string, severity types.Severity) {
	// order: v3.1 metrics => v3.0 metrics
	// save the first NVD metric
	for _, metricV3 := range append(metricsV31, metricsV30...) {
		if metricV3.Source == nvdSource {
			score = metricV3.CvssData.BaseScore
			vector = metricV3.CvssData.VectorString
			severity, _ = types.NewSeverity(metricV3.CvssData.BaseSeverity)
			return
		}
	}
	return
}

// getCvssV40 selects vector, score and severity from V40 metrics
func getCvssV40(metricsV40 []CvssMetricV40) (score float64, vector string, severity types.Severity) {
	for _, metricV40 := range metricsV40 {
		// save only NVD metric
		if metricV40.Source == nvdSource {
			score = metricV40.CvssData.BaseScore
			cvss40, err := gocvss40.ParseVector(strings.TrimSuffix(metricV40.CvssData.VectorString, "/"))
			if err != nil {
				log.WithPrefix("nvd").Warn("Failed to parse CVSSv4.0 vector",
					log.String("vector", metricV40.CvssData.VectorString),
					log.Err(err))
				return 0, "", types.SeverityUnknown
			}
			severity, _ = types.NewSeverity(metricV40.CvssData.BaseSeverity)
			return score, cvss40.Vector(), severity
		}
	}
	return
}

// Put saves a single CVE entry to the database.
func (nvd *NVD) Put(tx *bolt.Tx, cve Cve) error {
	cvssScore, cvssVector, severity := getCvssV2(cve.Metrics.CvssMetricV2)
	cvssScoreV3, cvssVectorV3, severityV3 := getCvssV3(cve.Metrics.CvssMetricV31, cve.Metrics.CvssMetricV30)
	cvssScoreV40, cvssVectorV40, severityV40 := getCvssV40(cve.Metrics.CvssMetricV40)

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
			if strings.HasPrefix(desc.Value, "CWE") {
				cweIDs = append(cweIDs, desc.Value)
			}
		}
	}

	publishedDate, _ := time.Parse("2006-01-02T15:04:05", cve.Published)
	lastModifiedDate, _ := time.Parse("2006-01-02T15:04:05", cve.LastModified)

	vuln := types.VulnerabilityDetail{
		CvssScore:        cvssScore,
		CvssVector:       cvssVector,
		CvssScoreV3:      cvssScoreV3,
		CvssVectorV3:     cvssVectorV3,
		CvssScoreV40:     cvssScoreV40,
		CvssVectorV40:    cvssVectorV40,
		Severity:         severity,
		SeverityV3:       severityV3,
		SeverityV40:      severityV40,
		CweIDs:           lo.Uniq(cweIDs),
		References:       references,
		Title:            "",
		Description:      description,
		PublishedDate:    &publishedDate,
		LastModifiedDate: &lastModifiedDate,
	}

	return nvd.PutVulnerabilityDetail(tx, cve.ID, vulnerability.NVD, vuln)
}
