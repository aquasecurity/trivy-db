package ubuntu

import (
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/stretchr/testify/assert"
	bolt "go.etcd.io/bbolt"
)

func TestVulnSrc_commit(t *testing.T) {
	tests := []struct {
		name                   string
		expectedErrorMsg       string
		cves                   []UbuntuCVE
		putVulnerabilityDetail []db.OperationPutVulnerabilityDetailExpectation
		putAdvisoryDetail      []db.OperationPutAdvisoryDetailExpectation
		putSeverity            []db.OperationPutSeverityExpectation
	}{
		{
			name: "happy path",
			cves: []UbuntuCVE{
				{
					Description: "test description",
					Candidate:   "CVE-2020-123",
					Priority:    "critical",
					Patches: map[PackageName]Patch{
						"test package": {
							"disco": Status{
								Status: "released",
								Note:   "v1.2.3",
							},
						},
						"test package2": {
							"disco": Status{
								Status: "released",
								Note:   "v2.3.4",
							},
						},
					},
					References: []string{"test reference 123"},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2020-123",
						Source:          "ubuntu 19.04",
						PkgName:         "test package",
						Advisory:        types.Advisory{FixedVersion: "v1.2.3"},
					},
				},
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2020-123",
						Source:          "ubuntu 19.04",
						PkgName:         "test package2",
						Advisory:        types.Advisory{FixedVersion: "v2.3.4"},
					},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2020-123",
						Source:          vulnerability.Ubuntu,
						Vulnerability: types.VulnerabilityDetail{
							Severity:    types.SeverityCritical,
							Description: "test description",
							References:  []string{"test reference 123"},
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
