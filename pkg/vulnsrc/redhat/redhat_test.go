package redhat

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	bolt "github.com/etcd-io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestMain(m *testing.M) {
	utils.Quiet = true
	os.Exit(m.Run())
}

func TestVulnSrc_Update(t *testing.T) {
	testCases := []struct {
		name             string
		cacheDir         string
		batchUpdateErr   error
		expectedErrorMsg string
		expectedVulns    []types.Advisory
	}{
		{
			name:     "happy1: AffectedRelease is an array",
			cacheDir: filepath.Join("testdata", "happy1"),
		},
		{
			name:     "happy2: AffectedRelease is an object",
			cacheDir: filepath.Join("testdata", "happy2"),
		},
		{
			name:     "happy3: PackageState is an array",
			cacheDir: filepath.Join("testdata", "happy3"),
		},
		{
			name:     "happy4: PackageState is an object",
			cacheDir: filepath.Join("testdata", "happy4"),
		},
		{
			name:             "sad1: AffectedRelease is an invalid array",
			cacheDir:         filepath.Join("testdata", "sad1"),
			expectedErrorMsg: "json: cannot unmarshal string into Go struct field RedhatCVEAffectedReleaseArray.affected_release of type redhat.RedhatAffectedRelease",
		},
		{
			name:             "sad2: AffectedRelease is an invalid object",
			cacheDir:         filepath.Join("testdata", "sad2"),
			expectedErrorMsg: "json: cannot unmarshal number into Go struct field RedhatAffectedRelease.affected_release.product_name of type string",
		},
		{
			name:             "sad3: PackageState is an invalid array",
			cacheDir:         filepath.Join("testdata", "sad3"),
			expectedErrorMsg: "json: cannot unmarshal string into Go struct field RedhatCVEPackageStateArray.package_state of type redhat.RedhatPackageState",
		},
		{
			name:             "sad4: PackageState is an invalid object",
			cacheDir:         filepath.Join("testdata", "sad4"),
			expectedErrorMsg: "json: cannot unmarshal number into Go struct field RedhatPackageState.package_state.product_name of type string",
		},
		{
			name:             "sad5: invalid JSON",
			cacheDir:         filepath.Join("testdata", "sad5"),
			expectedErrorMsg: "json: cannot unmarshal string into Go value of type redhat.RedhatCVE",
		},
		{
			name:             "sad6: AffectedRelease is an unknown type",
			cacheDir:         filepath.Join("testdata", "sad6"),
			expectedErrorMsg: "unknown affected_release type",
		},
		{
			name:             "sad7: PackageState is an unknown type",
			cacheDir:         filepath.Join("testdata", "sad7"),
			expectedErrorMsg: "unknown package_state type",
		},
		{
			name:             "cache dir doesnt exist",
			cacheDir:         "badpathdoesnotexist",
			expectedErrorMsg: "lstat badpathdoesnotexist/vuln-list/redhat: no such file or directory",
		},
		{
			name:             "unable to save redhat defintions",
			cacheDir:         filepath.Join("testdata", "happy1"),
			batchUpdateErr:   errors.New("unable to batch update"),
			expectedErrorMsg: "unable to batch update",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDBConfig := new(db.MockDBConfig)
			mockDBConfig.On("BatchUpdate", mock.Anything).Return(tc.batchUpdateErr)
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
	type putAdvisoryInput struct {
		source   string
		pkgName  string
		cveID    string
		advisory types.Advisory
	}
	type putAdvisory struct {
		input  putAdvisoryInput
		output error
	}

	type putVulnerabilityDetailInput struct {
		cveID  string
		source string
		vuln   types.VulnerabilityDetail
	}
	type putVulnerabilityDetail struct {
		input  putVulnerabilityDetailInput
		output error
	}

	type putSeverityInput struct {
		cveID    string
		severity types.Severity
	}
	type putSeverity struct {
		input  putSeverityInput
		output error
	}

	testCases := []struct {
		name                       string
		cves                       []RedhatCVE
		putAdvisoryList            []putAdvisory
		putVulnerabilityDetailList []putVulnerabilityDetail
		putSeverityList            []putSeverity
		expectedErrorMsg           string
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
					Cvss:           RedhatCvss{CvssBaseScore: "7.2"},
					Cvss3:          RedhatCvss3{Cvss3BaseScore: "4.0"},
					ThreatSeverity: "Moderate",
					References:     []string{"https://example.com"},
					Bugzilla:       RedhatBugzilla{Description: "CVE-2019-0160 package: title   "},
					Details:        []string{"detail1\n", "detail2"},
				},
			},
			putAdvisoryList: []putAdvisory{
				{
					input: putAdvisoryInput{
						source:   "Red Hat Enterprise Linux 6",
						pkgName:  "package",
						cveID:    "CVE-2019-0160",
						advisory: types.Advisory{FixedVersion: ""},
					},
				},
			},
			putVulnerabilityDetailList: []putVulnerabilityDetail{
				{
					input: putVulnerabilityDetailInput{
						cveID:  "CVE-2019-0160",
						source: vulnerability.RedHat,
						vuln: types.VulnerabilityDetail{
							CvssScore:   7.2,
							CvssScoreV3: 4.0,
							Severity:    types.SeverityMedium,
							References:  []string{"https://example.com"},
							Title:       "package: title",
							Description: "detail1\ndetail2",
						},
					},
				},
			},
			putSeverityList: []putSeverity{
				{
					input: putSeverityInput{
						cveID:    "CVE-2019-0160",
						severity: types.SeverityUnknown,
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
			putVulnerabilityDetailList: []putVulnerabilityDetail{
				{
					input: putVulnerabilityDetailInput{
						cveID:  "CVE-2019-9999",
						source: vulnerability.RedHat,
						vuln: types.VulnerabilityDetail{
							CvssScore:   0,
							CvssScoreV3: 5.1,
							Severity:    types.SeverityLow,
							Title:       "package: title!",
						},
					},
				},
			},
			putSeverityList: []putSeverity{
				{
					input: putSeverityInput{
						cveID:    "CVE-2019-9999",
						severity: types.SeverityUnknown,
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
			putVulnerabilityDetailList: []putVulnerabilityDetail{
				{
					input: putVulnerabilityDetailInput{
						cveID:  "CVE-2019-0001",
						source: vulnerability.RedHat,
						vuln: types.VulnerabilityDetail{
							CvssScore:   3.3,
							CvssScoreV3: 0,
							Severity:    types.SeverityHigh,
							Title:       "package: title",
						},
					},
				},
			},
			putSeverityList: []putSeverity{
				{
					input: putSeverityInput{
						cveID:    "CVE-2019-0001",
						severity: types.SeverityUnknown,
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
			putVulnerabilityDetailList: []putVulnerabilityDetail{
				{
					input: putVulnerabilityDetailInput{
						cveID:  "CVE-2018-0001",
						source: vulnerability.RedHat,
						vuln: types.VulnerabilityDetail{
							CvssScore:   10,
							CvssScoreV3: 9,
							Severity:    types.SeverityCritical,
							Title:       "test: title",
						},
					},
				},
			},
			putSeverityList: []putSeverity{
				{
					input: putSeverityInput{
						cveID:    "CVE-2018-0001",
						severity: types.SeverityUnknown,
					},
				},
			},
		},
		{
			name: "PutAdvisory returns an error",
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
			putAdvisoryList: []putAdvisory{
				{
					input: putAdvisoryInput{
						source:   "Red Hat Enterprise Linux 6",
						pkgName:  "package",
						cveID:    "CVE-2019-0160",
						advisory: types.Advisory{FixedVersion: ""},
					},
					output: errors.New("failed to put advisory"),
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
			putAdvisoryList: []putAdvisory{
				{
					input: putAdvisoryInput{
						source:   "Red Hat Enterprise Linux 6",
						pkgName:  "package",
						cveID:    "CVE-2019-0160",
						advisory: types.Advisory{FixedVersion: ""},
					},
				},
			},
			putVulnerabilityDetailList: []putVulnerabilityDetail{
				{
					input: putVulnerabilityDetailInput{
						cveID:  "CVE-2019-0160",
						source: vulnerability.RedHat,
						vuln: types.VulnerabilityDetail{
							CvssScore:   7.2,
							CvssScoreV3: 4.0,
							Severity:    types.SeverityMedium,
							References:  []string{"https://example.com"},
							Title:       "package: title",
							Description: "detail1\ndetail2",
						},
					},
					output: errors.New("failed to put vulnerability detail"),
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
			putAdvisoryList: []putAdvisory{
				{
					input: putAdvisoryInput{
						source:   "Red Hat Enterprise Linux 6",
						pkgName:  "package",
						cveID:    "CVE-2019-0160",
						advisory: types.Advisory{FixedVersion: ""},
					},
				},
			},
			putVulnerabilityDetailList: []putVulnerabilityDetail{
				{
					input: putVulnerabilityDetailInput{
						cveID:  "CVE-2019-0160",
						source: vulnerability.RedHat,
						vuln: types.VulnerabilityDetail{
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
			putSeverityList: []putSeverity{
				{
					input: putSeverityInput{
						cveID:    "CVE-2019-0160",
						severity: types.SeverityUnknown,
					},
					output: errors.New("failed to put severity"),
				},
			},
			expectedErrorMsg: "failed to put severity",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tx := &bolt.Tx{}
			mockDBConfig := new(db.MockDBConfig)
			for _, pa := range tc.putAdvisoryList {
				mockDBConfig.On("PutAdvisory", tx, pa.input.source, pa.input.pkgName,
					pa.input.cveID, pa.input.advisory).Return(pa.output)
			}
			for _, pvd := range tc.putVulnerabilityDetailList {
				mockDBConfig.On("PutVulnerabilityDetail", tx, pvd.input.cveID,
					pvd.input.source, pvd.input.vuln).Return(pvd.output)
			}
			for _, ps := range tc.putSeverityList {
				mockDBConfig.On("PutSeverity", tx, ps.input.cveID,
					ps.input.severity).Return(ps.output)
			}

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
	type getAdvisoriesInput struct {
		bucket  string
		pkgName string
	}
	type getAdvisoriesOutput struct {
		advisories []types.Advisory
		err        error
	}
	type getAdvisories struct {
		input  getAdvisoriesInput
		output getAdvisoriesOutput
	}
	testCases := []struct {
		name               string
		majorVersion       string
		pkgName            string
		getAdvisories      getAdvisories
		expectedErrorMsg   string
		expectedAdvisories []types.Advisory
	}{
		{
			name:         "happy path",
			majorVersion: "6",
			pkgName:      "package",
			getAdvisories: getAdvisories{
				input: getAdvisoriesInput{
					bucket:  "Red Hat Enterprise Linux 6",
					pkgName: "package",
				},
				output: getAdvisoriesOutput{
					advisories: []types.Advisory{{FixedVersion: "1.2.3"}},
				},
			},
			expectedAdvisories: []types.Advisory{{FixedVersion: "1.2.3"}},
		},
		{
			name:         "GetAdvisories returns an error",
			majorVersion: "6",
			pkgName:      "package",
			getAdvisories: getAdvisories{
				input: getAdvisoriesInput{
					bucket:  "Red Hat Enterprise Linux 6",
					pkgName: "package",
				},
				output: getAdvisoriesOutput{
					err: errors.New("failed to get advisories"),
				},
			},
			expectedErrorMsg:   "failed to get advisories",
			expectedAdvisories: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDBConfig := new(db.MockDBConfig)
			mockDBConfig.On("GetAdvisories", tc.getAdvisories.input.bucket,
				tc.getAdvisories.input.pkgName).Return(tc.getAdvisories.output.advisories,
				tc.getAdvisories.output.err)

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
