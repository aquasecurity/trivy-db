package debian

import (
	"testing"

	"github.com/stretchr/testify/assert"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

func TestVulnSrc_commit(t *testing.T) {
	tests := []struct {
		name                   string
		expectedErrorMsg       string
		cves                   []DebianCVE
		putAdvisoryDetail      []db.OperationPutAdvisoryDetailExpectation
		putVulnerabilityDetail []db.OperationPutVulnerabilityDetailExpectation
		putSeverity            []db.OperationPutSeverityExpectation
	}{
		{
			name: "happy path",
			cves: []DebianCVE{
				{
					Description:     "test description",
					Releases:        map[string]Release{"foo": {map[string]string{"buster": "bar"}, "open", "high"}},
					Scope:           "foo scope",
					Package:         "test package",
					VulnerabilityID: "CVE-2020-123",
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "debian 10",
						PkgName:         "test package",
						VulnerabilityID: "CVE-2020-123",
						Advisory:        types.Advisory{VulnerabilityID: "CVE-2020-123", FixedVersion: ""},
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
							Severity:    types.SeverityHigh,
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
			err := ac.commit(tx, tt.cves)
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
