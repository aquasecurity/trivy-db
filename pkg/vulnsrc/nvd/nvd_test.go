package nvd

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/utils"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/stretchr/testify/assert"
	bolt "go.etcd.io/bbolt"
)

func TestVulnSrc_Update(t *testing.T) {
	testCases := []struct {
		name    string
		dir     string
		cveID   string
		want    types.VulnerabilityDetail
		wantErr string
	}{
		{
			name:  "happy path",
			dir:   "./testdata",
			cveID: "CVE-2020-0001",
			want: types.VulnerabilityDetail{
				Description:      "In getProcessRecordLocked of ActivityManagerService.java isolated apps are not handled correctly. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Product: Android Versions: Android-8.0, Android-8.1, Android-9, and Android-10 Android ID: A-140055304",
				CvssScore:        7.2,
				CvssVector:       "AV:L/AC:L/Au:N/C:C/I:C/A:C",
				CvssScoreV3:      7.8,
				CvssVectorV3:     "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
				Severity:         types.SeverityHigh,
				SeverityV3:       types.SeverityHigh,
				CweIDs:           []string{"CWE-269"},
				References:       []string{"https://source.android.com/security/bulletin/2020-01-01"},
				LastModifiedDate: utils.MustTimeParse("2020-01-01T01:01:00Z"),
				PublishedDate:    utils.MustTimeParse("2001-01-01T01:01:00Z"),
			},
		},
		{
			name:    "sad path",
			dir:     "./sad",
			wantErr: "no such file or directory",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cacheDir, err := ioutil.TempDir("", "nvd")
			require.NoError(t, err)
			err = db.Init(cacheDir)
			require.NoError(t, err)
			defer db.Close()
			defer os.RemoveAll(cacheDir)

			vs := NewVulnSrc()
			err = vs.Update(tc.dir)

			switch {
			case tc.wantErr != "":
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tc.wantErr, tc.name)
			default:
				assert.NoError(t, err, tc.name)
				dbc := db.Config{}
				got, err := dbc.GetVulnerabilityDetail(tc.cveID)
				require.NoError(t, err)
				assert.Equal(t, tc.want, got["nvd"])
			}
		})
	}
}
func TestVulnSrc_Commit(t *testing.T) {
	testCases := []struct {
		name                   string
		cves                   []Item
		putAdvisoryDetail      []db.OperationPutAdvisoryDetailExpectation
		putVulnerabilityDetail []db.OperationPutVulnerabilityDetailExpectation
		putSeverity            []db.OperationPutSeverityExpectation
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
					PublishedDate:    "2006-01-02T15:04Z",
					LastModifiedDate: "2020-01-02T15:04Z",
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2017-0012",
						Source:          vulnerability.NVD,
						Vulnerability: types.VulnerabilityDetail{
							CvssScore:        4.3,
							CvssVector:       "AV:N/AC:M/Au:N/C:N/I:P/A:N",
							CvssScoreV3:      9.4,
							CvssVectorV3:     "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
							Severity:         types.SeverityMedium,
							SeverityV3:       types.SeverityHigh,
							References:       []string{"https://example.com"},
							Description:      "some description",
							PublishedDate:    utils.MustTimeParse("2006-01-02T15:04:00Z"),
							LastModifiedDate: utils.MustTimeParse("2020-01-02T15:04:00Z"),
						},
					},
				},
			},
		},
		{
			name: "happy path with **REJECT** in description",
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
									Value: "** REJECT ** test description",
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
					PublishedDate:    "2006-01-02T15:04Z",
					LastModifiedDate: "2020-01-02T15:04Z",
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2017-0012",
						Source:          vulnerability.NVD,
						Vulnerability: types.VulnerabilityDetail{
							CvssScore:        4.3,
							CvssVector:       "AV:N/AC:M/Au:N/C:N/I:P/A:N",
							CvssScoreV3:      9.4,
							CvssVectorV3:     "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
							Severity:         types.SeverityMedium,
							SeverityV3:       types.SeverityHigh,
							References:       []string{"https://example.com"},
							Description:      "** REJECT ** test description",
							PublishedDate:    utils.MustTimeParse("2006-01-02T15:04:00Z"),
							LastModifiedDate: utils.MustTimeParse("2020-01-02T15:04:00Z"),
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
			mockDBConfig.ApplyPutAdvisoryDetailExpectations(tc.putAdvisoryDetail)
			mockDBConfig.ApplyPutVulnerabilityDetailExpectations(tc.putVulnerabilityDetail)
			mockDBConfig.ApplyPutSeverityExpectations(tc.putSeverity)

			ac := VulnSrc{dbc: mockDBConfig}
			err := ac.commit(tx, tc.cves)

			switch {
			case tc.expectedErrorMsg != "":
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrorMsg, tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}
			mockDBConfig.AssertExpectations(t)
		})
	}
}
