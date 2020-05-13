package nvd

import (
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/stretchr/testify/assert"
	bolt "go.etcd.io/bbolt"
)

func TestVulnSrc_Commit(t *testing.T) {
	testCases := []struct {
		name                   string
		cves                   []Item
		putAdvisory            []db.PutAdvisoryExpectation
		putVulnerabilityDetail []db.PutVulnerabilityDetailExpectation
		putSeverity            []db.PutSeverityExpectation
		expectedErrorMsg       string
	}{
		{
			name: "happy path",
			cves: []Item{
				{
					Cve: Cve{
						Meta: Meta{
							ID: "CVE-2017-0012",
						},
						References: References{
							ReferenceDataList: []ReferenceData{
								{
									Name:      "reference1",
									Refsource: "SECTRACK",
									URL:       "https://example.com",
								},
							},
						},
						Description: Description{
							DescriptionDataList: []DescriptionData{
								{
									Lang:  "en",
									Value: "some description",
								},
							},
						},
					},
					Impact: Impact{
						BaseMetricV2: BaseMetricV2{
							CvssV2: CvssV2{
								BaseScore:    4.3,
								VectorString: "AV:N/AC:M/Au:N/C:N/I:P/A:N",
							},
							Severity: "MEDIUM",
						},
						BaseMetricV3: BaseMetricV3{
							CvssV3: CvssV3{
								BaseScore:    9.4,
								BaseSeverity: "HIGH",
								VectorString: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
							},
						},
					},
				},
			},
			putVulnerabilityDetail: []db.PutVulnerabilityDetailExpectation{
				{
					Args: db.PutVulnerabilityDetailArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2017-0012",
						Source:          vulnerability.Nvd,
						Vulnerability: types.VulnerabilityDetail{
							CvssScore:    4.3,
							CvssVector:   "AV:N/AC:M/Au:N/C:N/I:P/A:N",
							CvssScoreV3:  9.4,
							CvssVectorV3: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
							Severity:     types.SeverityMedium,
							SeverityV3:   types.SeverityHigh,
							References:   []string{"https://example.com"},
							Description:  "some description",
						},
					},
				},
			},
		},

		// TODO: Add sad paths
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tx := &bolt.Tx{}
			mockDBConfig := new(db.MockOperation)
			mockDBConfig.ApplyPutAdvisoryExpectations(tc.putAdvisory)
			mockDBConfig.ApplyPutVulnerabilityDetailExpectations(tc.putVulnerabilityDetail)
			mockDBConfig.ApplyPutSeverityExpectations(tc.putSeverity)

			ac := VulnSrc{dbc: mockDBConfig}
			err := ac.commit(tx, tc.cves)

			switch {
			case tc.expectedErrorMsg != "":
				assert.Contains(t, err.Error(), tc.expectedErrorMsg, tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}
			mockDBConfig.AssertExpectations(t)
		})
	}
}
