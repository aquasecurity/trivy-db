package amazon

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/vuln-list-update/amazon"
	"github.com/stretchr/testify/assert"
	bolt "go.etcd.io/bbolt"
)

func TestMain(m *testing.M) {
	utils.Quiet = true
	os.Exit(m.Run())
}

func TestVulnSrc_Update(t *testing.T) {
	testCases := []struct {
		name          string
		cacheDir      string
		batchUpdate   db.OperationBatchUpdateExpectation
		expectedError error
		expectedVulns []types.Advisory
	}{
		{
			name:     "happy path",
			cacheDir: "testdata",
			batchUpdate: db.OperationBatchUpdateExpectation{
				Args: db.OperationBatchUpdateArgs{FnAnything: true},
			},
		},
		{
			name:     "cache dir doesnt exist",
			cacheDir: "badpathdoesnotexist",
			batchUpdate: db.OperationBatchUpdateExpectation{
				Args: db.OperationBatchUpdateArgs{FnAnything: true},
			},
			expectedError: errors.New("error in Amazon walk: error in file walk: lstat badpathdoesnotexist/vuln-list/amazon: no such file or directory"),
		},
		{
			name:     "unable to save amazon defintions",
			cacheDir: "testdata",
			batchUpdate: db.OperationBatchUpdateExpectation{
				Args: db.OperationBatchUpdateArgs{FnAnything: true},
				Returns: db.OperationBatchUpdateReturns{
					Err: errors.New("unable to batch update"),
				},
			},
			expectedError: errors.New("error in Amazon save: error in batch update: unable to batch update"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDBConfig := new(db.MockOperation)
			mockDBConfig.ApplyBatchUpdateExpectation(tc.batchUpdate)
			ac := VulnSrc{dbc: mockDBConfig}

			err := ac.Update(tc.cacheDir)
			switch {
			case tc.expectedError != nil:
				assert.EqualError(t, err, tc.expectedError.Error(), tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}
		})
	}
}

func TestVulnSrc_Get(t *testing.T) {
	testCases := []struct {
		name          string
		version       string
		pkgName       string
		getAdvisories db.OperationGetAdvisoriesExpectation
		expectedError error
		expectedVulns []types.Advisory
	}{
		{
			name:    "happy path",
			version: "1",
			pkgName: "curl",
			getAdvisories: db.OperationGetAdvisoriesExpectation{
				Args: db.OperationGetAdvisoriesArgs{
					Source:  "amazon linux 1",
					PkgName: "curl",
				},
				Returns: db.OperationGetAdvisoriesReturns{
					Advisories: []types.Advisory{
						{VulnerabilityID: "CVE-2019-0001", FixedVersion: "0.1.2"},
					},
				},
			},
			expectedVulns: []types.Advisory{{VulnerabilityID: "CVE-2019-0001", FixedVersion: "0.1.2"}},
		},
		{
			name:    "no advisories are returned",
			version: "2",
			pkgName: "bash",
			getAdvisories: db.OperationGetAdvisoriesExpectation{
				Args: db.OperationGetAdvisoriesArgs{
					Source:  "amazon linux 2",
					PkgName: "bash",
				},
				Returns: db.OperationGetAdvisoriesReturns{},
			},
		},
		{
			name: "amazon GetAdvisories return an error",
			getAdvisories: db.OperationGetAdvisoriesExpectation{
				Args: db.OperationGetAdvisoriesArgs{
					SourceAnything:  true,
					PkgNameAnything: true,
				},
				Returns: db.OperationGetAdvisoriesReturns{
					Advisories: []types.Advisory{},
					Err:        xerrors.New("unable to get advisories"),
				},
			},
			expectedError: errors.New("failed to get Amazon advisories: unable to get advisories"),
			expectedVulns: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDBConfig := new(db.MockOperation)
			mockDBConfig.ApplyGetAdvisoriesExpectation(tc.getAdvisories)

			ac := VulnSrc{dbc: mockDBConfig}
			vuls, err := ac.Get(tc.version, tc.pkgName)

			switch {
			case tc.expectedError != nil:
				assert.EqualError(t, err, tc.expectedError.Error(), tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}
			assert.Equal(t, tc.expectedVulns, vuls, tc.name)
		})
	}
}

func TestSeverityFromPriority(t *testing.T) {
	testCases := map[string]types.Severity{
		"low":       types.SeverityLow,
		"medium":    types.SeverityMedium,
		"important": types.SeverityHigh,
		"critical":  types.SeverityCritical,
		"unknown":   types.SeverityUnknown,
	}
	for k, v := range testCases {
		assert.Equal(t, v, severityFromPriority(k))
	}
}

func TestConstructVersion(t *testing.T) {
	type inputCombination struct {
		epoch   string
		version string
		release string
	}

	testCases := []struct {
		name            string
		inc             inputCombination
		expectedVersion string
	}{
		{
			name: "happy path",
			inc: inputCombination{
				epoch:   "2",
				version: "3",
				release: "master",
			},
			expectedVersion: "2:3-master",
		},
		{
			name: "no epoch",
			inc: inputCombination{
				version: "2",
				release: "master",
			},
			expectedVersion: "2-master",
		},
		{
			name: "no release",
			inc: inputCombination{
				epoch:   "",
				version: "2",
			},
			expectedVersion: "2",
		},
		{
			name: "no epoch and release",
			inc: inputCombination{
				version: "2",
			},
			expectedVersion: "2",
		},
		{
			name:            "no epoch release or version",
			inc:             inputCombination{},
			expectedVersion: "",
		},
	}

	for _, tc := range testCases {
		assert.Equal(t, tc.expectedVersion, constructVersion(tc.inc.epoch, tc.inc.version, tc.inc.release), tc.name)
	}
}

func TestVulnSrc_WalkFunc(t *testing.T) {
	testCases := []struct {
		name             string
		ioReader         io.Reader
		inputPath        string
		expectedALASList []alas
		expectedError    error
		expectedLogs     []string
	}{
		{
			name: "happy path",
			ioReader: strings.NewReader(`{
"id":"123",
"severity":"high"
}`),
			inputPath: "1/2/1",
			expectedALASList: []alas{
				{
					Version: "2",
					ALAS: amazon.ALAS{
						ID:       "123",
						Severity: "high",
					},
				},
			},
			expectedError: nil,
		},
		{
			name:             "amazon returns invalid json",
			ioReader:         strings.NewReader(`invalidjson`),
			inputPath:        "1/2/1",
			expectedALASList: []alas(nil),
			expectedError:    errors.New("failed to decode Amazon JSON: invalid character 'i' looking for beginning of value"),
		},
		{
			name:          "unsupported amazon version",
			inputPath:     "foo/bar/baz",
			expectedError: nil,
			expectedLogs:  []string{"unsupported amazon version: bar"},
		},
		{
			name:          "empty path",
			inputPath:     "",
			expectedError: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ac := VulnSrc{}

			err := ac.walkFunc(tc.ioReader, tc.inputPath)
			switch {
			case tc.expectedError != nil:
				assert.EqualError(t, err, tc.expectedError.Error(), tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}

			assert.Equal(t, tc.expectedALASList, ac.alasList, tc.name)
		})
	}
}

func TestVulnSrc_CommitFunc(t *testing.T) {
	testCases := []struct {
		name                       string
		alasList                   []alas
		putAdvisoryDetail          []db.OperationPutAdvisoryDetailExpectation
		putVulnerabilityDetail     []db.OperationPutVulnerabilityDetailExpectation
		putSeverity                []db.OperationPutSeverityExpectation
		getAdvisoryDetail          db.OperationGetAdvisoryDetailExpectation
		putSecurityAdvisoryDetails db.OperationPutSecurityAdvisoryDetailsExpectation
		expectedError              error
	}{
		{
			name: "happy path",
			alasList: []alas{
				{
					Version: "123",

					ALAS: amazon.ALAS{
						ID:       "123",
						Severity: "important",
						CveIDs:   []string{"CVE-2020-0001"},
						Issued:   amazon.Date{Date: "2018-04-26 17:41"},
						References: []amazon.Reference{
							{
								ID:    "fooref",
								Href:  "http://foo.bar/baz",
								Title: "bartitle",
							},
						},
						Packages: []amazon.Package{
							{
								Name:    "testpkg",
								Epoch:   "123",
								Version: "456",
								Release: "testing",
							},
						},
					},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "amazon linux 123",
						PkgName:         "testpkg",
						VulnerabilityID: "CVE-2020-0001",
						Advisory:        types.Advisory{FixedVersion: "123:456-testing", SecurityAdvisory: []string{"456", "123"}},
					},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2020-0001",
						Source:          vulnerability.Amazon,

						Vulnerability: types.VulnerabilityDetail{
							CvssScore:   0,
							CvssScoreV3: 0,
							Severity:    types.SeverityHigh,
							References:  []string{"http://foo.bar/baz"},
						},
					},
				},
			},
			putSeverity: []db.OperationPutSeverityExpectation{
				{
					Args: db.OperationPutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2020-0001",
						Severity:        types.SeverityUnknown,
					},
				},
			},
			getAdvisoryDetail: db.OperationGetAdvisoryDetailExpectation{
				Args: db.OperationGetAdvisoryDetailArgs{
					CveID:        "CVE-2020-0001",
					PlatformName: "amazon linux 123",
					PkgName:      "testpkg",
				},
				Returns: db.OperationGetAdvisoryDetailReturns{
					Details: types.AdvisoryDetail{
						PlatformName: "amazon linux 123",
						PackageName:  "testpkg",
						AdvisoryItem: types.Advisory{FixedVersion: "123:456-testing", SecurityAdvisory: []string{"456"}},
					},
				},
			},
			putSecurityAdvisoryDetails: db.OperationPutSecurityAdvisoryDetailsExpectation{
				Args: db.OperationPutSecurityAdvisoryDetailsArgs{
					TxAnything: true,
					CveID:      "CVE-2020-0001",
					Source:     "amazon",
					SecurityAdvisory: map[string]types.SecurityAdvisory{
						"123": {
							Severity:    "important",
							Description: "",
							PublishDate: time.Date(2018, 4, 26, 17, 41, 0, 0, time.UTC),
						},
					},
				},
			},
		},
		{
			name: "failed to save Amazon advisory, PutAdvisory() return an error",
			alasList: []alas{
				{
					Version: "123",
					ALAS: amazon.ALAS{
						ID:       "123",
						Severity: "high",
						CveIDs:   []string{"CVE-2020-0001"},
						References: []amazon.Reference{
							{
								ID:    "fooref",
								Href:  "http://foo.bar/baz",
								Title: "bartitle",
							},
						},
						Packages: []amazon.Package{
							{
								Name:    "testpkg",
								Epoch:   "123",
								Version: "456",
								Release: "testing",
							},
						},
					},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "amazon linux 123",
						PkgName:         "testpkg",
						VulnerabilityID: "CVE-2020-0001",
						Advisory:        types.Advisory{FixedVersion: "123:456-testing", SecurityAdvisory: []string{"123"}},
					},
					Returns: db.OperationPutAdvisoryDetailReturns{
						Err: errors.New("failed to put advisory"),
					},
				},
			},
			getAdvisoryDetail: db.OperationGetAdvisoryDetailExpectation{
				Args: db.OperationGetAdvisoryDetailArgs{
					CveID:        "CVE-2020-0001",
					PlatformName: "amazon linux 123",
					PkgName:      "testpkg",
				},
				Returns: db.OperationGetAdvisoryDetailReturns{
					Details: types.AdvisoryDetail{
						PlatformName: "amazon linux 123",
						PackageName:  "testpkg",
						AdvisoryItem: types.Advisory{FixedVersion: "123:456-testing"},
					},
				},
			},
			expectedError: errors.New("failed to save Amazon advisory: failed to put advisory"),
		},
		{
			name: "failed to save Amazon advisory, PutVulnerabilityDetail() returns an error",
			alasList: []alas{
				{
					Version: "123",
					ALAS: amazon.ALAS{
						ID:       "123",
						Severity: "important",
						CveIDs:   []string{"CVE-2020-0001"},
						References: []amazon.Reference{
							{
								ID:    "fooref",
								Href:  "http://foo.bar/baz",
								Title: "bartitle",
							},
						},
						Packages: []amazon.Package{
							{
								Name:    "testpkg",
								Epoch:   "123",
								Version: "456",
								Release: "testing",
							},
						},
					},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "amazon linux 123",
						PkgName:         "testpkg",
						VulnerabilityID: "CVE-2020-0001",
						Advisory:        types.Advisory{FixedVersion: "123:456-testing", SecurityAdvisory: []string{"123"}},
					},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2020-0001",
						Source:          vulnerability.Amazon,
						Vulnerability: types.VulnerabilityDetail{
							CvssScore:   0,
							CvssScoreV3: 0,
							Severity:    types.SeverityHigh,
							References:  []string{"http://foo.bar/baz"},
						},
					},
					Returns: db.OperationPutVulnerabilityDetailReturns{
						Err: errors.New("failed to put vulnerability detail"),
					},
				},
			},
			getAdvisoryDetail: db.OperationGetAdvisoryDetailExpectation{
				Args: db.OperationGetAdvisoryDetailArgs{
					CveID:        "CVE-2020-0001",
					PlatformName: "amazon linux 123",
					PkgName:      "testpkg",
				},
				Returns: db.OperationGetAdvisoryDetailReturns{
					Details: types.AdvisoryDetail{
						PlatformName: "amazon linux 123",
						PackageName:  "testpkg",
						AdvisoryItem: types.Advisory{FixedVersion: "123:456-testing"},
					},
				},
			},
			expectedError: errors.New("failed to save Amazon vulnerability detail: failed to put vulnerability detail"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDBConfig := new(db.MockOperation)
			mockDBConfig.ApplyPutAdvisoryDetailExpectations(tc.putAdvisoryDetail)
			mockDBConfig.ApplyPutVulnerabilityDetailExpectations(tc.putVulnerabilityDetail)
			mockDBConfig.ApplyPutSeverityExpectations(tc.putSeverity)
			mockDBConfig.ApplyGetAdvisoryDetailExpectation(tc.getAdvisoryDetail)
			mockDBConfig.ApplyPutSecurityAdvisoryDetailsExpectation(tc.putSecurityAdvisoryDetails)
			vs := VulnSrc{dbc: mockDBConfig, alasList: tc.alasList}

			err := vs.commitFunc(&bolt.Tx{WriteFlag: 0})
			switch {
			case tc.expectedError != nil:
				assert.EqualError(t, err, tc.expectedError.Error(), tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}
		})
	}
}
