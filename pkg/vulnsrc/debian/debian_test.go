package debian

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/knqyf263/nested"
	"github.com/stretchr/testify/assert"
	bolt "go.etcd.io/bbolt"
)

func TestVulnSrc_commit(t *testing.T) {
	tests := []struct {
		name                   string
		expectedErrorMsg       string
		buckets                nested.Nested
		putAdvisoryDetail      []db.OperationPutAdvisoryDetailExpectation
		putVulnerabilityDetail []db.OperationPutVulnerabilityDetailExpectation
		putSeverity            []db.OperationPutSeverityExpectation
	}{
		{
			name: "happy path",
			buckets: map[string]interface{}{
				"debian 10": map[string]interface{}{
					"test package": map[string]interface{}{
						"CVE-2020-123": VulnDetail{
							FixedVersion: "1.3.5-6",
							State:        "fixed",
							Description:  "test description",
							Severity:     types.SeverityLow,
						},
					},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "debian 10",
						PkgName:         "test package",
						VulnerabilityID: "CVE-2020-123",
						Advisory: VulnDetail{
							FixedVersion: "1.3.5-6",
							State:        "fixed",
							Description:  "test description",
							Severity:     types.SeverityLow,
						},
					},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2020-123",
						Source:          vulnerability.Debian,
						Vulnerability: types.VulnerabilityDetail{
							Severity:    types.SeverityLow,
							Description: "test description",
						},
					},
				},
			},
			putSeverity: []db.OperationPutSeverityExpectation{
				{
					Args: db.OperationPutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2020-123",
						Severity:        types.SeverityUnknown,
					},
				},
			},
		},

		// TODO: Add other test cases for failing paths
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := &bolt.Tx{}
			mockDBConfig := new(db.MockOperation)
			mockDBConfig.ApplyPutAdvisoryDetailExpectations(tt.putAdvisoryDetail)
			mockDBConfig.ApplyPutVulnerabilityDetailExpectations(tt.putVulnerabilityDetail)
			mockDBConfig.ApplyPutSeverityExpectations(tt.putSeverity)

			ac := VulnSrc{dbc: mockDBConfig}
			err := ac.commit(tx, tt.buckets)
			switch {
			case tt.expectedErrorMsg != "":
				assert.Contains(t, err.Error(), tt.expectedErrorMsg, tt.name)
			default:
				assert.NoError(t, err, tt.name)
			}
			mockDBConfig.AssertExpectations(t)
		})
	}
}

func TestVulnSrc_parseDebianFiles(t *testing.T) {
	rootdir, _ := os.Getwd()

	tests := []struct {
		name             string
		expectedErrorMsg string
		dir              string
		buckets          nested.Nested
	}{
		{
			name: "end to end",
			dir:  filepath.Join(rootdir, "testdata/dir1"),
			buckets: map[string]interface{}{
				"debian 12": map[string]interface{}{
					"openssl": map[string]interface{}{
						"CVE-2014-0076": VulnDetail{
							FixedVersion: "0.9.8o-4squeeze15",
							State:        "fixed",
							Description:  "(The Montgomery ladder implementation in OpenSSL through 1.0.0l does no ...)",
							VendorIds:    []string{"DLA-0003-1"},
						},
						"DLA-0003-1": VulnDetail{
							FixedVersion: "0.9.8o-4squeeze15",
							State:        "fixed",
							Description:  "openssl - security update",
							Severity:     types.SeverityUnknown,
						},
						"DSA-2908-1": VulnDetail{
							FixedVersion: "1.0.1e-2+deb7u7",
							State:        "fixed",
							Description:  "openssl - security update",
							Severity:     types.SeverityLow,
						},
					},
				},
				"debian unstable": map[string]interface{}{
					"openssl": map[string]interface{}{
						"CVE-2014-0076": VulnDetail{
							FixedVersion: "1.0.1g-1",
							State:        "fixed",
							Description:  "(The Montgomery ladder implementation in OpenSSL through 1.0.0l does no ...)",
							Severity:     types.SeverityUnknown,
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac := NewVulnSrc()
			buckets, err := ac.parseDebianFiles(tt.dir)

			assert.Equal(t, tt.buckets, buckets)
			switch {
			case tt.expectedErrorMsg != "":
				assert.Contains(t, err.Error(), tt.expectedErrorMsg, tt.name)
			default:
				assert.NoError(t, err, tt.name)
			}
		})
	}
}
