package suseoval

import (
	"errors"
	"os"
	"testing"

	bolt "github.com/etcd-io/bbolt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/xerrors"

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
		name           string
		cacheDir       string
		batchUpdateErr error
		expectedError  error
		expectedVulns  []types.Advisory
	}{
		{
			name:     "happy path",
			cacheDir: "testdata",
		},
		{
			name:          "cache dir doesnt exist",
			cacheDir:      "badpathdoesnotexist",
			expectedError: nil,
		},
		{
			name:           "unable to save oracle linux oval defintions",
			cacheDir:       "testdata",
			batchUpdateErr: errors.New("unable to batch update"),
			expectedError:  errors.New("error in SUSE OVAL save: error in batch update: unable to batch update"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDBConfig := new(db.MockDBConfig)
			mockDBConfig.On("BatchUpdate", mock.Anything).Return(tc.batchUpdateErr)
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
		cves                       []SuseOVAL
		platformName               string
		putAdvisoryList            []putAdvisory
		putVulnerabilityDetailList []putVulnerabilityDetail
		putSeverityList            []putSeverity
		expectedErrorMsg           string
	}{
		{
			name:         "opensuse leap happy path nomal json",
			platformName: "OpenSUSE Leap 15.0",
			cves: []SuseOVAL{
				{
					Title:       "CVE-2019-9628",
					Description: "The XMLTooling library all versions prior to V3.0.4, provided with the OpenSAML and Shibboleth Service Provider software, contains an XML parsing class. Invalid data in the XML declaration causes an exception of a type that was not handled properly in the parser class and propagates an unexpected exception type.",
					Platform:    []string{"openSUSE Leap 15.0"},
					References: []Reference{
						{
							Source: "CVE",
							URI:    "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9628",
							ID:     "CVE-2019-9628",
						},
					},
					Criteria: Criteria{
						Operator: "AND",
						Criterias: []Criteria{
							{
								Operator: "OR",
								Criterias: []Criteria{
									{
										Operator:  "AND",
										Criterias: nil,
										Criterions: []Criterion{
											{
												Comment: "libxmltooling-devel-1.6.4-lp150.2.3 is installed",
											},
											{
												Comment: "libxmltooling-devel is signed with openSUSE key",
											},
										},
									},
								},
								Criterions: nil,
							},
						},
						Criterions: []Criterion{
							{
								Comment: "openSUSE Leap 15.0 is installed",
							},
						},
					},
					Severity: "Moderate",
					Cve:      "CVE-2019-9628",
				},
			},
			putAdvisoryList: []putAdvisory{
				{
					input: putAdvisoryInput{
						source:   "OpenSUSE Leap 15.0",
						pkgName:  "libxmltooling-devel",
						cveID:    "CVE-2019-9628",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "1.6.4-lp150.2.3"},
					},
				},
			},
			putVulnerabilityDetailList: []putVulnerabilityDetail{
				{
					input: putVulnerabilityDetailInput{
						cveID:  "CVE-2019-9628",
						source: vulnerability.SuseOVAL,
						vuln: types.VulnerabilityDetail{
							Description: "The XMLTooling library all versions prior to V3.0.4, provided with the OpenSAML and Shibboleth Service Provider software, contains an XML parsing class. Invalid data in the XML declaration causes an exception of a type that was not handled properly in the parser class and propagates an unexpected exception type.",
							References: []string{
								"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9628",
							},
							Title:    "CVE-2019-9628",
							Severity: types.SeverityMedium,
						},
					},
				},
			},
			putSeverityList: []putSeverity{
				{
					input: putSeverityInput{
						cveID:    "CVE-2019-9628",
						severity: types.SeverityUnknown,
					},
				},
			},
		},
		{
			name:         "SUSE Enterprise happy path 'less than format' json",
			platformName: "SUSE Enterprise Linux 10",
			cves: []SuseOVAL{
				{
					Title:       "CVE-2013-1667",
					Description: "The rehash mechanism in Perl 5.8.2 through 5.16.x allows context-dependent attackers to cause a denial of service (memory consumption and crash) via a crafted hash key.",
					Platform: []string{
						"SUSE Linux Enterprise Server 10 SP4 for AMD64 and Intel EM64T",
						"SUSE Linux Enterprise Server 10 SP4 for IBM POWER",
						"SUSE Linux Enterprise Server 10 SP4 for IBM zSeries 64bit",
						"SUSE Linux Enterprise Server 10 SP4 for IPF",
						"SUSE Linux Enterprise Server 10 SP4 for x86",
						"SUSE Linux Enterprise Teradata 10 SP3 for AMD64 and Intel EM64T",
					},
					References: []Reference{
						{
							Source: "CVE",
							URI:    "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-1667",
							ID:     "CVE-2013-1667",
						},
					},
					Criteria: Criteria{
						Operator: "AND",
						Criterias: []Criteria{
							{
								Operator:  "OR",
								Criterias: nil,
								Criterions: []Criterion{
									{
										Comment: "perl-32bit less than 5.8.8-14.21.3",
									},
									{
										Comment: "perl-64bit less than 5.8.8-14.21.3",
									},
								},
							},
						},
						Criterions: []Criterion{
							{
								Comment: "sles10-sp4 is installed",
							},
						},
					},
					Severity: "",
					Cve:      "CVE-2013-1667",
				},
			},
			putAdvisoryList: []putAdvisory{
				{
					input: putAdvisoryInput{
						source:   "SUSE Enterprise Linux 10",
						pkgName:  "perl-32bit",
						cveID:    "CVE-2013-1667",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "5.8.8-14.21.3"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "SUSE Enterprise Linux 10",
						pkgName:  "perl-64bit",
						cveID:    "CVE-2013-1667",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "5.8.8-14.21.3"},
					},
				},
			},
			putVulnerabilityDetailList: []putVulnerabilityDetail{
				{
					input: putVulnerabilityDetailInput{
						cveID:  "CVE-2013-1667",
						source: vulnerability.SuseOVAL,
						vuln: types.VulnerabilityDetail{
							Description: "The rehash mechanism in Perl 5.8.2 through 5.16.x allows context-dependent attackers to cause a denial of service (memory consumption and crash) via a crafted hash key.",
							References: []string{
								"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-1667",
							},
							Title:    "CVE-2013-1667",
							Severity: types.SeverityUnknown,
						},
					},
				},
			},
			putSeverityList: []putSeverity{
				{
					input: putSeverityInput{
						cveID:    "CVE-2013-1667",
						severity: types.SeverityUnknown,
					},
				},
			},
		},
		{
			name:         "SUSE Enterprise Server happy path 'criteria empty' json",
			platformName: "SUSE Enterprise Linux 11",
			cves: []SuseOVAL{
				{
					Title:       "CVE-2011-5321",
					Description: "The tty_open function in drivers/tty/tty_io.c in the Linux kernel before 3.1.1 mishandles a driver-lookup failure, which allows local users to cause a denial of service (NULL pointer dereference and system crash) or possibly have unspecified other im    pact via crafted access to a device file under the /dev/pts directory.",
					Platform: []string{
						"SUSE Linux Enterprise Server 11 SP1-TERADATA",
						"SUSE Linux Enterprise Server for SAP Applications 11 SP1-TERADATA",
					},
					References: []Reference{
						{
							Source: "CVE",
							URI:    "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-5321",
							ID:     "CVE-2011-5321",
						},
					},
					Criteria: Criteria{
						Operator:   "",
						Criterias:  nil,
						Criterions: nil,
					},
					Severity: "Moderate",
					Cve:      "CVE-2011-5321",
				},
			},
			putAdvisoryList:            []putAdvisory{},
			putVulnerabilityDetailList: []putVulnerabilityDetail{},
			putSeverityList:            []putSeverity{},
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
			err := ac.commit(tx, tc.cves, tc.platformName)

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

func TestSeverityFromThreat(t *testing.T) {
	testCases := map[string]types.Severity{
		"Low":       types.SeverityLow,
		"Moderate":  types.SeverityMedium,
		"Important": types.SeverityHigh,
		"Critical":  types.SeverityCritical,
		"":          types.SeverityUnknown,
	}
	for k, v := range testCases {
		assert.Equal(t, v, severityFromThreat(k))
	}
}

func TestVulnSrc_Get(t *testing.T) {
	type getAdvisoriesInput struct {
		version string
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
		name          string
		release       string
		pkgName       string
		getAdvisories getAdvisories
		expectedError error
		expectedVulns []types.Advisory
	}{
		{
			name:    "happy path OpenSUSE",
			release: "OpenSUSE Leap 15.1",
			pkgName: "binutils",
			getAdvisories: getAdvisories{
				input: getAdvisoriesInput{
					version: "OpenSUSE Leap 15.1",
					pkgName: "binutils",
				},
				output: getAdvisoriesOutput{
					advisories: []types.Advisory{
						{VulnerabilityID: "CVE-2019-1010180", FixedVersion: "2.32-lp151.3.3"},
					},
					err: nil,
				},
			},
			expectedError: nil,
			expectedVulns: []types.Advisory{{VulnerabilityID: "CVE-2019-1010180", FixedVersion: "2.32-lp151.3.3"}},
		},
		{
			name:    "happy path SUSE Enterprise Linux",
			release: "SUSE Enterprise Linux 12",
			pkgName: "znc",
			getAdvisories: getAdvisories{
				input: getAdvisoriesInput{
					version: "SUSE Enterprise Linux 12",
					pkgName: "znc",
				},
				output: getAdvisoriesOutput{
					advisories: []types.Advisory{
						{VulnerabilityID: "CVE-2019-9917", FixedVersion: "1.7.2-23"},
					},
					err: nil,
				},
			},
			expectedError: nil,
			expectedVulns: []types.Advisory{{VulnerabilityID: "CVE-2019-9917", FixedVersion: "1.7.2-23"}},
		},
		{
			name:    "no advisories are returned",
			release: "OpenSUSE Leap 15.1",
			pkgName: "no-package",
			getAdvisories: getAdvisories{
				input: getAdvisoriesInput{
					version: "OpenSUSE Leap 15.1",
					pkgName: "no-package",
				},
				output: getAdvisoriesOutput{advisories: []types.Advisory{}, err: nil},
			},
			expectedError: nil,
			expectedVulns: []types.Advisory{},
		},
		{
			name: "oracle GetAdvisories return an error",
			getAdvisories: getAdvisories{
				input: getAdvisoriesInput{
					version: mock.Anything,
					pkgName: mock.Anything,
				},
				output: getAdvisoriesOutput{
					advisories: []types.Advisory{},
					err:        xerrors.New("unable to get advisories"),
				},
			},
			expectedError: errors.New("failed to get SUSE advisories: unable to get advisories"),
			expectedVulns: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDBConfig := new(db.MockDBConfig)
			mockDBConfig.On("GetAdvisories",
				tc.getAdvisories.input.version, tc.getAdvisories.input.pkgName).Return(
				tc.getAdvisories.output.advisories, tc.getAdvisories.output.err,
			)

			ac := VulnSrc{dbc: mockDBConfig}
			vuls, err := ac.Get(tc.release, tc.pkgName)

			switch {
			case tc.expectedError != nil:
				assert.EqualError(t, err, tc.expectedError.Error(), tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}
			assert.Equal(t, tc.expectedVulns, vuls, tc.name)

			mockDBConfig.AssertExpectations(t)
		})
	}
}
