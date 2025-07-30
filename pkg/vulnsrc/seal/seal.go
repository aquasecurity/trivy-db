package seal

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	bolt "go.etcd.io/bbolt"
)

const (
	sealVulnerabilitiesPath = "/Users/yotameliraz/trivy_poc/trivy-db-cache/cache/seal-vulnerabilities-osv.json"
)

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc:      db.Config{},
		sourceID: "seal",
	}
}

func (v VulnSrc) Name() types.SourceID {
	return v.sourceID
}

func (v VulnSrc) createDataSource(dataSourceName, dataSourceURL string) types.DataSource {
	return types.DataSource{
		ID:   v.sourceID,
		Name: dataSourceName,
		URL:  dataSourceURL,
	}
}

func createVulnerabilityDetail(title, description, reference string, cvssScore float64, published, lastModified string, severity types.Severity) types.VulnerabilityDetail {
	return types.VulnerabilityDetail{
		Title:       title,
		Description: description,
		Severity:    severity,
		References:  []string{reference},
		CvssScoreV3: cvssScore,
		PublishedDate: func() *time.Time {
			t, _ := time.Parse(time.RFC3339, published)
			return &t
		}(),
		LastModifiedDate: func() *time.Time {
			t, _ := time.Parse(time.RFC3339, lastModified)
			return &t
		}(),
	}
}

func (v VulnSrc) putVulnerabilityDetail(tx *bolt.Tx, data VulnerabilityData) error {
	dataSource := v.createDataSource("Seal Vulnerability Source", data.DataSourceURL)
	if err := v.dbc.PutDataSource(tx, data.Bucket, dataSource); err != nil {
		return err
	}
	vulnDetail := createVulnerabilityDetail(data.Title, data.Description, data.Reference, data.CvssScore, data.Published, data.LastModified, data.Severity)
	if err := v.dbc.PutVulnerabilityDetail(tx, data.CveID, v.sourceID, vulnDetail); err != nil {
		return err
	}
	if err := v.dbc.PutVulnerabilityID(tx, data.CveID); err != nil {
		return err
	}
	return nil
}

func (v VulnSrc) Update(root string) error {
	file, err := os.Open(sealVulnerabilitiesPath)
	if err != nil {
		return fmt.Errorf("failed to open SEAL vulnerabilities file: %w", err)
	}
	defer file.Close()

	var osvEntries []OSVEntry
	if err := json.NewDecoder(file).Decode(&osvEntries); err != nil {
		return fmt.Errorf("failed to decode SEAL vulnerabilities JSON: %w", err)
	}

	return v.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		for _, entry := range osvEntries {
			if entry.Withdrawn != nil && entry.Withdrawn.Before(time.Now()) {
				continue
			}

			cvssScore := parseCVSSScore(entry.Severities)
			severity := cvssScoreToSeverity(cvssScore)

			var reference string
			if len(entry.References) > 0 {
				reference = entry.References[0].URL
			}

			for _, affected := range entry.Affected {
				bucket := strings.ReplaceAll(affected.Package.Ecosystem, ":", " ")
				vulnData := VulnerabilityData{
					CveID:          entry.ID,
					PkgName:        affected.Package.Name,
					Bucket:         bucket,
					DataSourceName: "Seal Vulnerability Source",
					DataSourceURL:  "https://seal.example.com",
					Title:          entry.Summary,
					Description:    entry.Details,
					Reference:      reference,
					CvssScore:      cvssScore,
					Published:      entry.Published.Format(time.RFC3339),
					LastModified:   entry.Modified.Format(time.RFC3339),
					Severity:       severity,
				}

				var advisory any
				var pkgName, advisoryBucket string
				if isOracleEntry(entry) {
					rpmData := processOracleEntry(entry, vulnData)
					advisory = createRpmAdvisory(rpmData)
					pkgName = rpmData.PkgName
					advisoryBucket = rpmData.Bucket
				} else {
					osvData := processOsvEntry(affected, vulnData)
					advisory = createOsvAdvisory(osvData)
					pkgName = osvData.PkgName
					advisoryBucket = osvData.Bucket
				}

				if err := v.putVulnerabilityDetail(tx, vulnData); err != nil {
					return fmt.Errorf("failed to save vulnerability detail for %s: %w", entry.ID, err)
				}
				if err := v.dbc.PutAdvisoryDetail(tx, entry.ID, pkgName, []string{advisoryBucket}, advisory); err != nil {
					return fmt.Errorf("failed to save advisory data for %s: %w", entry.ID, err)
				}
			}
		}
		return nil
	})
} 