package redhat

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

func TestMain(m *testing.M) {
	utils.Quiet = true
	os.Exit(m.Run())
}

func TestVulnSrc_Update(t *testing.T) {
	testCases := []struct {
		name             string
		cacheDir         string
		batchUpdate      db.OperationBatchUpdateExpectation
		expectedErrorMsg string
		expectedVulns    []types.Advisory
	}{
		{
			name:     "happy1: AffectedRelease is an array",
			cacheDir: filepath.Join("testdata", "happy1"),
			batchUpdate: db.OperationBatchUpdateExpectation{
				Args: db.OperationBatchUpdateArgs{FnAnything: true},
			},
		},
		{
			name:     "happy2: AffectedRelease is an object",
			cacheDir: filepath.Join("testdata", "happy2"),
			batchUpdate: db.OperationBatchUpdateExpectation{
				Args: db.OperationBatchUpdateArgs{FnAnything: true},
			},
		},
		{
			name:     "happy3: PackageState is an array",
			cacheDir: filepath.Join("testdata", "happy3"),
			batchUpdate: db.OperationBatchUpdateExpectation{
				Args: db.OperationBatchUpdateArgs{FnAnything: true},
			},
		},
		{
			name:     "happy4: PackageState is an object",
			cacheDir: filepath.Join("testdata", "happy4"),
			batchUpdate: db.OperationBatchUpdateExpectation{
				Args: db.OperationBatchUpdateArgs{FnAnything: true},
			},
		},
		{
			name:     "sad1: AffectedRelease is an invalid array",
			cacheDir: filepath.Join("testdata", "sad1"),
			batchUpdate: db.OperationBatchUpdateExpectation{
				Args: db.OperationBatchUpdateArgs{FnAnything: true},
			},
			expectedErrorMsg: "json: cannot unmarshal string into Go struct field RedhatCVEAffectedReleaseArray.affected_release of type redhat.RedhatAffectedRelease",
		},
		{
			name:     "sad2: AffectedRelease is an invalid object",
			cacheDir: filepath.Join("testdata", "sad2"),
			batchUpdate: db.OperationBatchUpdateExpectation{
				Args: db.OperationBatchUpdateArgs{FnAnything: true},
			},
			expectedErrorMsg: "json: cannot unmarshal number into Go struct field RedhatAffectedRelease.affected_release.product_name of type string",
		},
		{
			name:     "sad3: PackageState is an invalid array",
			cacheDir: filepath.Join("testdata", "sad3"),
			batchUpdate: db.OperationBatchUpdateExpectation{
				Args: db.OperationBatchUpdateArgs{FnAnything: true},
			},
			expectedErrorMsg: "json: cannot unmarshal string into Go struct field RedhatCVEPackageStateArray.package_state of type redhat.RedhatPackageState",
		},
		{
			name:     "sad4: PackageState is an invalid object",
			cacheDir: filepath.Join("testdata", "sad4"),
			batchUpdate: db.OperationBatchUpdateExpectation{
				Args: db.OperationBatchUpdateArgs{FnAnything: true},
			},
			expectedErrorMsg: "json: cannot unmarshal number into Go struct field RedhatPackageState.package_state.product_name of type string",
		},
		{
			name:     "sad5: invalid JSON",
			cacheDir: filepath.Join("testdata", "sad5"),
			batchUpdate: db.OperationBatchUpdateExpectation{
				Args: db.OperationBatchUpdateArgs{FnAnything: true},
			},
			expectedErrorMsg: "json: cannot unmarshal string into Go value of type redhat.RedhatCVE",
		},
		{
			name:     "sad6: AffectedRelease is an unknown type",
			cacheDir: filepath.Join("testdata", "sad6"),
			batchUpdate: db.OperationBatchUpdateExpectation{
				Args: db.OperationBatchUpdateArgs{FnAnything: true},
			},
			expectedErrorMsg: "unknown affected_release type",
		},
		{
			name:     "sad7: PackageState is an unknown type",
			cacheDir: filepath.Join("testdata", "sad7"),
			batchUpdate: db.OperationBatchUpdateExpectation{
				Args: db.OperationBatchUpdateArgs{FnAnything: true},
			},
			expectedErrorMsg: "unknown package_state type",
		},
		{
			name:     "cache dir doesnt exist",
			cacheDir: "badpathdoesnotexist",
			batchUpdate: db.OperationBatchUpdateExpectation{
				Args: db.OperationBatchUpdateArgs{FnAnything: true},
			},
			expectedErrorMsg: "lstat badpathdoesnotexist/vuln-list/redhat: no such file or directory",
		},
		{
			name:     "unable to save redhat defintions",
			cacheDir: filepath.Join("testdata", "happy1"),
			batchUpdate: db.OperationBatchUpdateExpectation{
				Args: db.OperationBatchUpdateArgs{FnAnything: true},
				Returns: db.OperationBatchUpdateReturns{
					Err: errors.New("unable to batch update"),
				},
			},
			expectedErrorMsg: "unable to batch update",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDBConfig := new(db.MockOperation)
			mockDBConfig.ApplyBatchUpdateExpectation(tc.batchUpdate)
			ac := VulnSrc{dbc: mockDBConfig}

			err := ac.Update(tc.cacheDir)
			switch {
			case tc.expectedErrorMsg != "":
				assert.Contains(t, err.Error(), tc.expectedErrorMsg, tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}
		})
	}
}

func TestVulnSrc_Commit(t *testing.T) {
	testCases := []struct {
		name                   string
		cves                   []RedhatCVE
		putAdvisoryDetail      []db.OperationPutAdvisoryDetailExpectation
		putVulnerabilityDetail []db.OperationPutVulnerabilityDetailExpectation
		putSeverity            []db.OperationPutSeverityExpectation
		expectedErrorMsg       string
	}{
		{
			name: "happy path",
			cves: []RedhatCVE{
				{
					Name: "CVE-2019-0160",
					PackageState: []RedhatPackageState{
						{
							PackageName: "package",
							ProductName: "Red Hat Enterprise Linux 6",
							FixState:    "Will not fix",
						},
					},
					Cvss:           RedhatCvss{CvssBaseScore: "7.2", CvssScoringVector: "(AV:N/AC:L/Au:N/C:P/I:P/A:P)"},
					Cvss3:          RedhatCvss3{Cvss3BaseScore: "4.0", Cvss3ScoringVector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
					ThreatSeverity: "Moderate",
					References:     []string{"https://example.com"},
					Bugzilla:       RedhatBugzilla{Description: "CVE-2019-0160 package: title   "},
					Details:        []string{"detail1\n", "detail2"},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "Red Hat Enterprise Linux 6",
						PkgName:         "package",
						VulnerabilityID: "CVE-2019-0160",
						Advisory:        types.Advisory{FixedVersion: ""},
					},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2019-0160",
						Source:          vulnerability.RedHat,
						Vulnerability: types.VulnerabilityDetail{
							CvssScore:    7.2,
							CvssVector:   "(AV:N/AC:L/Au:N/C:P/I:P/A:P)",
							CvssScoreV3:  4.0,
							CvssVectorV3: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
							Severity:     types.SeverityMedium,
							References:   []string{"https://example.com"},
							Title:        "package: title",
							Description:  "detail1\ndetail2",
						},
					},
				},
			},
			putSeverity: []db.OperationPutSeverityExpectation{
				{
					Args: db.OperationPutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2019-0160",
						Severity:        types.SeverityUnknown,
					},
				},
			},
		},
		{
			name: "empty package name",
			cves: []RedhatCVE{
				{
					Name: "CVE-2019-9999",
					PackageState: []RedhatPackageState{
						{PackageName: ""}, // empty
					},
					Cvss:           RedhatCvss{CvssBaseScore: "invalid"}, // ignored
					Cvss3:          RedhatCvss3{Cvss3BaseScore: "5.1"},
					ThreatSeverity: "Low",
					Bugzilla:       RedhatBugzilla{Description: "CVE-2019-9999 package: title!"},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2019-9999",
						Source:          vulnerability.RedHat,
						Vulnerability: types.VulnerabilityDetail{
							CvssScore:   0,
							CvssScoreV3: 5.1,
							Severity:    types.SeverityLow,
							Title:       "package: title!",
						},
					},
				},
			},
			putSeverity: []db.OperationPutSeverityExpectation{
				{
					Args: db.OperationPutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2019-9999",
						Severity:        types.SeverityUnknown,
					},
				},
			},
		},
		{
			name: "unknown platform",
			cves: []RedhatCVE{
				{
					Name: "CVE-2019-0001",
					PackageState: []RedhatPackageState{
						{
							PackageName: "test",
							ProductName: "Red Hat Enterprise Linux 10000", // unknown
						},
					},
					Cvss:           RedhatCvss{CvssBaseScore: "3.3"},
					Cvss3:          RedhatCvss3{Cvss3BaseScore: "dummy"}, // ignored
					ThreatSeverity: "Important",
					Bugzilla:       RedhatBugzilla{Description: "CVE-2019-0001 package: title"},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2019-0001",
						Source:          vulnerability.RedHat,
						Vulnerability: types.VulnerabilityDetail{
							CvssScore:   3.3,
							CvssScoreV3: 0,
							Severity:    types.SeverityHigh,
							Title:       "package: title",
						},
					},
				},
			},
			putSeverity: []db.OperationPutSeverityExpectation{
				{
					Args: db.OperationPutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2019-0001",
						Severity:        types.SeverityUnknown,
					},
				},
			},
		},
		{
			name: "unknown status",
			cves: []RedhatCVE{
				{
					Name: "CVE-2018-0001",
					PackageState: []RedhatPackageState{
						{
							PackageName: "test",
							ProductName: "Red Hat Enterprise Linux 6",
							FixState:    "Danger", // unknown
						},
					},
					Cvss:           RedhatCvss{CvssBaseScore: "10"},
					Cvss3:          RedhatCvss3{Cvss3BaseScore: "9"},
					ThreatSeverity: "Critical",
					Bugzilla:       RedhatBugzilla{Description: "CVE-2018-0001 test: title"},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2018-0001",
						Source:          vulnerability.RedHat,
						Vulnerability: types.VulnerabilityDetail{
							CvssScore:   10,
							CvssScoreV3: 9,
							Severity:    types.SeverityCritical,
							Title:       "test: title",
						},
					},
				},
			},
			putSeverity: []db.OperationPutSeverityExpectation{
				{
					Args: db.OperationPutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2018-0001",
						Severity:        types.SeverityUnknown,
					},
				},
			},
		},
		{
			name: "PutAdvisoryDetail returns an error",
			cves: []RedhatCVE{
				{
					Name: "CVE-2019-0160",
					PackageState: []RedhatPackageState{
						{
							PackageName: "package",
							ProductName: "Red Hat Enterprise Linux 6",
							FixState:    "Will not fix",
						},
					},
					Cvss:           RedhatCvss{CvssBaseScore: "7.2"},
					Cvss3:          RedhatCvss3{Cvss3BaseScore: "4.0"},
					ThreatSeverity: "Moderate",
					References:     []string{"https://example.com"},
					Bugzilla:       RedhatBugzilla{Description: "CVE-2019-0160 package: title   "},
					Details:        []string{"detail1\n", "detail2"},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "Red Hat Enterprise Linux 6",
						PkgName:         "package",
						VulnerabilityID: "CVE-2019-0160",
						Advisory:        types.Advisory{FixedVersion: ""},
					},
					Returns: db.OperationPutAdvisoryDetailReturns{
						Err: errors.New("failed to put advisory"),
					},
				},
			},
			expectedErrorMsg: "failed to put advisory",
		},
		{
			name: "PutVulnerabilityDetail returns an error",
			cves: []RedhatCVE{
				{
					Name: "CVE-2019-0160",
					PackageState: []RedhatPackageState{
						{
							PackageName: "package",
							ProductName: "Red Hat Enterprise Linux 6",
							FixState:    "Will not fix",
						},
					},
					Cvss:           RedhatCvss{CvssBaseScore: "7.2"},
					Cvss3:          RedhatCvss3{Cvss3BaseScore: "4.0"},
					ThreatSeverity: "Moderate",
					References:     []string{"https://example.com"},
					Bugzilla:       RedhatBugzilla{Description: "CVE-2019-0160 package: title   "},
					Details:        []string{"detail1\n", "detail2"},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "Red Hat Enterprise Linux 6",
						PkgName:         "package",
						VulnerabilityID: "CVE-2019-0160",
						Advisory:        types.Advisory{FixedVersion: ""},
					},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2019-0160",
						Source:          vulnerability.RedHat,
						Vulnerability: types.VulnerabilityDetail{
							CvssScore:   7.2,
							CvssScoreV3: 4.0,
							Severity:    types.SeverityMedium,
							References:  []string{"https://example.com"},
							Title:       "package: title",
							Description: "detail1\ndetail2",
						},
					},
					Returns: db.OperationPutVulnerabilityDetailReturns{
						Err: errors.New("failed to put vulnerability detail"),
					},
				},
			},
			expectedErrorMsg: "failed to put vulnerability detail",
		},
		{
			name: "PutSeverity returns an error",
			cves: []RedhatCVE{
				{
					Name: "CVE-2019-0160",
					PackageState: []RedhatPackageState{
						{
							PackageName: "package",
							ProductName: "Red Hat Enterprise Linux 6",
							FixState:    "Will not fix",
						},
					},
					Cvss:           RedhatCvss{CvssBaseScore: "7.2"},
					Cvss3:          RedhatCvss3{Cvss3BaseScore: "4.0"},
					ThreatSeverity: "Unknown",
					References:     []string{"https://example.com"},
					Bugzilla:       RedhatBugzilla{Description: "CVE-2019-0160 package: title   "},
					Details:        []string{"detail1\n", "detail2"},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "Red Hat Enterprise Linux 6",
						PkgName:         "package",
						VulnerabilityID: "CVE-2019-0160",
						Advisory:        types.Advisory{FixedVersion: ""},
					},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2019-0160",
						Source:          vulnerability.RedHat,
						Vulnerability: types.VulnerabilityDetail{
							CvssScore:   7.2,
							CvssScoreV3: 4.0,
							Severity:    types.SeverityUnknown,
							References:  []string{"https://example.com"},
							Title:       "package: title",
							Description: "detail1\ndetail2",
						},
					},
				},
			},
			putSeverity: []db.OperationPutSeverityExpectation{
				{
					Args: db.OperationPutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2019-0160",
						Severity:        types.SeverityUnknown,
					},
					Returns: db.OperationPutSeverityReturns{
						Err: errors.New("failed to put severity"),
					},
				},
			},
			expectedErrorMsg: "failed to put severity",
		},
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
				assert.Contains(t, err.Error(), tc.expectedErrorMsg, tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}
			mockDBConfig.AssertExpectations(t)
		})
	}
}

func TestVulnSrc_Get(t *testing.T) {
	testCases := []struct {
		name               string
		majorVersion       string
		pkgName            string
		getAdvisories      db.OperationGetAdvisoriesExpectation
		expectedErrorMsg   string
		expectedAdvisories []types.Advisory
	}{
		{
			name:         "happy path",
			majorVersion: "6",
			pkgName:      "package",
			getAdvisories: db.OperationGetAdvisoriesExpectation{
				Args: db.OperationGetAdvisoriesArgs{
					Source:  "Red Hat Enterprise Linux 6",
					PkgName: "package",
				},
				Returns: db.OperationGetAdvisoriesReturns{
					Advisories: []types.Advisory{{FixedVersion: "1.2.3"}},
				},
			},
			expectedAdvisories: []types.Advisory{{FixedVersion: "1.2.3"}},
		},
		{
			name:         "GetAdvisories returns an error",
			majorVersion: "6",
			pkgName:      "package",
			getAdvisories: db.OperationGetAdvisoriesExpectation{
				Args: db.OperationGetAdvisoriesArgs{
					Source:  "Red Hat Enterprise Linux 6",
					PkgName: "package",
				},
				Returns: db.OperationGetAdvisoriesReturns{
					Err: errors.New("failed to get advisories"),
				},
			},
			expectedErrorMsg:   "failed to get advisories",
			expectedAdvisories: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDBConfig := new(db.MockOperation)
			mockDBConfig.ApplyGetAdvisoriesExpectation(tc.getAdvisories)

			vs := VulnSrc{dbc: mockDBConfig}
			advisories, err := vs.Get(tc.majorVersion, tc.pkgName)

			switch {
			case tc.expectedErrorMsg != "":
				assert.Contains(t, err.Error(), tc.expectedErrorMsg, tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}

			assert.ElementsMatch(t, advisories, tc.expectedAdvisories, tc.name)

			mockDBConfig.AssertExpectations(t)
		})
	}
}
