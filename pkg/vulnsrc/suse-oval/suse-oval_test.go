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
			expectedError: errors.New("error in SUSE OVAL walk: error in file walk: lstat badpathdoesnotexist/vuln-list/oval/suse: no such file or directory"),
		},
		{
			name:           "unable to save suse linux oval defintions",
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
		putAdvisoryList            []putAdvisory
		putVulnerabilityDetailList []putVulnerabilityDetail
		putSeverityList            []putSeverity
		expectedErrorMsg           string
	}{
		{
			name: "opensuse leap happy path nomal json",
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
			name: "SUSE Enterprise happy path 'less than format' json",
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
						source:   "SUSE Linux Enterprise 10.4",
						pkgName:  "perl-32bit",
						cveID:    "CVE-2013-1667",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "5.8.8-14.21.3"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "SUSE Linux Enterprise 10.4",
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
			name: "openSUSE Leap 42.3 happy path 'Operator AND OR AND' json",
			cves: []SuseOVAL{
				{
					Title:       "CVE-2012-6150",
					Description: "The winbind_name_list_to_sid_string_list function in nsswitch/pam_winbind.c in Samba through 4.1.2 handles invalid require_membership_of group names by accepting authentication by any user, which allows remote authenticated users to bypass intended access restrictions in opportunistic circumstances by leveraging an administrator's pam_winbind configuration-file mistake.",
					Platform: []string{
						"openSUSE Leap 42.3",
					},
					References: []Reference{
						{
							Source: "CVE",
							URI:    "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-6150",
							ID:     "CVE-2012-6150",
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
												Comment: "libdcerpc-binding0-4.6.5+git.32.af7a173b7a1-1 is installed",
											},
											{
												Comment: "libdcerpc-binding0 is signed with openSUSE key",
											},
										},
									},
									{
										Operator:  "AND",
										Criterias: nil,
										Criterions: []Criterion{
											{
												Comment: "libdcerpc-binding0-32bit-4.6.5+git.32.af7a173b7a1-1 is installed",
											},
											{
												Comment: "libdcerpc-binding0-32bit is signed with openSUSE key",
											},
										},
									},
								},
								Criterions: nil,
							},
						},
						Criterions: []Criterion{
							{
								Comment: "openSUSE Leap 42.3 is installed",
							},
						},
					},
					Severity: "",
					Cve:      "CVE-2012-6150",
				},
			},
			putAdvisoryList: []putAdvisory{
				{
					input: putAdvisoryInput{
						source:   "OpenSUSE Leap 42.3",
						pkgName:  "libdcerpc-binding0-32bit",
						cveID:    "CVE-2012-6150",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "4.6.5+git.32.af7a173b7a1-1"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "OpenSUSE Leap 42.3",
						pkgName:  "libdcerpc-binding0",
						cveID:    "CVE-2012-6150",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "4.6.5+git.32.af7a173b7a1-1"},
					},
				},
			},
			putVulnerabilityDetailList: []putVulnerabilityDetail{
				{
					input: putVulnerabilityDetailInput{
						cveID:  "CVE-2012-6150",
						source: vulnerability.SuseOVAL,
						vuln: types.VulnerabilityDetail{
							Description: "The winbind_name_list_to_sid_string_list function in nsswitch/pam_winbind.c in Samba through 4.1.2 handles invalid require_membership_of group names by accepting authentication by any user, which allows remote authenticated users to bypass intended access restrictions in opportunistic circumstances by leveraging an administrator's pam_winbind configuration-file mistake.",
							References: []string{
								"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-6150",
							},
							Title:    "CVE-2012-6150",
							Severity: types.SeverityUnknown,
						},
					},
				},
			},
			putSeverityList: []putSeverity{
				{
					input: putSeverityInput{
						cveID:    "CVE-2012-6150",
						severity: types.SeverityUnknown,
					},
				},
			},
		},
		{
			name: "SUSE Linux Enterprise Desktop 12 happy path 'Multiformat operator 1' json",
			cves: []SuseOVAL{
				{
					Title:       "CVE-2013-2486",
					Description: "The dissect_diagnosticrequest function in epan/dissectors/packet-reload.c in the REsource LOcation And Discovery (aka RELOAD) dissector in Wireshark 1.8.x before 1.8.6 uses an incorrect integer data type, which allows remote attackers to cause a denial of service (infinite loop) via crafted integer values in a packet.",
					Platform: []string{
						"SUSE Linux Enterprise Desktop 12",
						"SUSE Linux Enterprise Desktop 12 SP1",
						"SUSE Linux Enterprise Desktop 12 SP2",
						"SUSE Linux Enterprise Desktop 12 SP3",
						"SUSE Linux Enterprise Desktop 12 SP4",
					},
					References: []Reference{
						{
							Source: "CVE",
							URI:    "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-2486",
							ID:     "CVE-2013-2486",
						},
					},
					Criteria: Criteria{
						Operator: "OR",
						Criterias: []Criteria{
							{
								Operator:  "AND",
								Criterias: nil,
								Criterions: []Criterion{
									{
										Comment: "SUSE Linux Enterprise Desktop 12 is installed",
									},
									{
										Comment: "wireshark-1.10.9-1 is installed",
									},
								},
							},
							{
								Operator:  "AND",
								Criterias: nil,
								Criterions: []Criterion{
									{
										Comment: "SUSE Linux Enterprise Desktop 12 SP1 is installed",
									},
									{
										Comment: "wireshark-1.12.7-15 is installed",
									},
								},
							},
							{
								Operator:  "AND",
								Criterias: nil,
								Criterions: []Criterion{
									{
										Comment: "SUSE Linux Enterprise Desktop 12 SP2 is installed",
									},
									{
										Comment: "wireshark-1.12.13-31 is installed",
									},
								},
							},
							{
								Operator: "AND",
								Criterias: []Criteria{
									{
										Operator:  "OR",
										Criterias: nil,
										Criterions: []Criterion{
											{
												Comment: "libwireshark8-2.2.7-47 is installed",
											},
											{
												Comment: "libwiretap6-2.2.7-47 is installed",
											},
										},
									},
								},
								Criterions: []Criterion{
									{
										Comment: "SUSE Linux Enterprise Desktop 12 SP3 is installed",
									},
								},
							},
						},
						Criterions: nil,
					},
					Severity: "Moderate",
					Cve:      "CVE-2013-2486",
				},
			},
			putAdvisoryList: []putAdvisory{
				{
					input: putAdvisoryInput{
						source:   "SUSE Linux Enterprise 12",
						pkgName:  "wireshark",
						cveID:    "CVE-2013-2486",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "1.10.9-1"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "SUSE Linux Enterprise 12.1",
						pkgName:  "wireshark",
						cveID:    "CVE-2013-2486",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "1.12.7-15"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "SUSE Linux Enterprise 12.2",
						pkgName:  "wireshark",
						cveID:    "CVE-2013-2486",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "1.12.13-31"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "SUSE Linux Enterprise 12.3",
						pkgName:  "libwireshark8",
						cveID:    "CVE-2013-2486",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "2.2.7-47"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "SUSE Linux Enterprise 12.3",
						pkgName:  "libwiretap6",
						cveID:    "CVE-2013-2486",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "2.2.7-47"},
					},
				},
			},
			putVulnerabilityDetailList: []putVulnerabilityDetail{
				{
					input: putVulnerabilityDetailInput{
						cveID:  "CVE-2013-2486",
						source: vulnerability.SuseOVAL,
						vuln: types.VulnerabilityDetail{
							Description: "The dissect_diagnosticrequest function in epan/dissectors/packet-reload.c in the REsource LOcation And Discovery (aka RELOAD) dissector in Wireshark 1.8.x before 1.8.6 uses an incorrect integer data type, which allows remote attackers to cause a denial of service (infinite loop) via crafted integer values in a packet.",
							References: []string{
								"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-2486",
							},
							Title:    "CVE-2013-2486",
							Severity: types.SeverityMedium,
						},
					},
				},
			},
			putSeverityList: []putSeverity{
				{
					input: putSeverityInput{
						cveID:    "CVE-2013-2486",
						severity: types.SeverityUnknown,
					},
				},
			},
		},
		{
			name: "SUSE Linux Enterprise Desktop 12 happy path 'Multiformat operator 2' json",
			cves: []SuseOVAL{
				{
					Title:       "CVE-2015-5310",
					Description: "The WNM Sleep Mode code in wpa_supplicant 2.x before 2.6 does not properly ignore key data in response frames when management frame protection (MFP) was not negotiated, which allows remote attackers to inject arbitrary broadcast or multicast packets or cause a denial of service (ignored packets) via a WNM Sleep Mode response.",
					Platform: []string{

						"SUSE Linux Enterprise Desktop 12 SP1",
						"SUSE Linux Enterprise Desktop 12 SP2",
						"SUSE Linux Enterprise Desktop 12 SP3",
						"SUSE Linux Enterprise Desktop 12 SP4",
					},
					References: []Reference{
						{
							Source: "CVE",
							URI:    "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5310",
							ID:     "CVE-2015-5310",
						},
					},
					Criteria: Criteria{
						Operator: "OR",
						Criterias: []Criteria{
							{
								Operator: "AND",
								Criterias: []Criteria{
									{
										Operator:  "OR",
										Criterias: nil,
										Criterions: []Criterion{
											{
												Comment: "SUSE Linux Enterprise Desktop 12 SP1 is installed",
											},
											{
												Comment: "SUSE Linux Enterprise Desktop 12 SP2 is installed",
											},
										},
									},
								},
								Criterions: []Criterion{
									{
										Comment: "wpa_supplicant-2.2-14 is installed",
									},
								},
							},
							{
								Operator:  "AND",
								Criterias: nil,
								Criterions: []Criterion{
									{
										Comment: "SUSE Linux Enterprise Desktop 12 SP4 is installed",
									},
									{
										Comment: "wpa_supplicant-2.2-15.3 is installed",
									},
								},
							},
						},
						Criterions: nil,
					},
					Severity: "Moderate",
					Cve:      "CVE-2015-5310",
				},
			},
			putAdvisoryList: []putAdvisory{
				{
					input: putAdvisoryInput{
						source:   "SUSE Linux Enterprise 12.1",
						pkgName:  "wpa_supplicant",
						cveID:    "CVE-2015-5310",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "2.2-14"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "SUSE Linux Enterprise 12.2",
						pkgName:  "wpa_supplicant",
						cveID:    "CVE-2015-5310",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "2.2-14"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "SUSE Linux Enterprise 12.4",
						pkgName:  "wpa_supplicant",
						cveID:    "CVE-2015-5310",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "2.2-15.3"},
					},
				},
			},
			putVulnerabilityDetailList: []putVulnerabilityDetail{
				{
					input: putVulnerabilityDetailInput{
						cveID:  "CVE-2015-5310",
						source: vulnerability.SuseOVAL,
						vuln: types.VulnerabilityDetail{
							Description: "The WNM Sleep Mode code in wpa_supplicant 2.x before 2.6 does not properly ignore key data in response frames when management frame protection (MFP) was not negotiated, which allows remote attackers to inject arbitrary broadcast or multicast packets or cause a denial of service (ignored packets) via a WNM Sleep Mode response.",
							References: []string{
								"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-5310",
							},
							Title:    "CVE-2015-5310",
							Severity: types.SeverityMedium,
						},
					},
				},
			},
			putSeverityList: []putSeverity{
				{
					input: putSeverityInput{
						cveID:    "CVE-2015-5310",
						severity: types.SeverityUnknown,
					},
				},
			},
		},
		{
			name: "openSUSE Leap 15.0 happy path 'Multiformat operator 3' json",
			cves: []SuseOVAL{
				{
					Title:       "CVE-2018-6148",
					Description: "Incorrect implementation in Content Security Policy in Google Chrome prior to 67.0.3396.79 allowed a remote attacker to bypass navigation restrictions via a crafted HTML page.",
					Platform: []string{
						"openSUSE Leap 15.0",
						"openSUSE Leap 15.0 NonFree",
					},
					References: []Reference{
						{
							Source: "CVE",
							URI:    "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6148",
							ID:     "CVE-2018-6148",
						},
					},
					Criteria: Criteria{
						Operator: "OR",
						Criterias: []Criteria{
							{
								Operator: "AND",
								Criterias: []Criteria{
									{
										Operator:  "AND",
										Criterias: nil,
										Criterions: []Criterion{
											{
												Comment: "opera-54.0.2952.41-lp150.2.3 is installed",
											},
											{
												Comment: "opera is signed with openSUSE key",
											},
										},
									},
								},
								Criterions: []Criterion{
									{
										Comment: "openSUSE Leap 15.0 NonFree is installed",
									},
								},
							},
							{
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
														Comment: "chromedriver-67.0.3396.99-lp150.2.3 is installed",
													},
													{
														Comment: "chromedriver is signed with openSUSE key",
													},
												},
											},
											{
												Operator:  "AND",
												Criterias: nil,
												Criterions: []Criterion{
													{
														Comment: "chromium-67.0.3396.99-lp150.2.3 is installed",
													},
													{
														Comment: "chromium is signed with openSUSE key",
													},
												},
											},
										},
										Criterions: nil},
								},
								Criterions: []Criterion{
									{
										Comment: "openSUSE Leap 15.0 is installed",
									},
								},
							},
						},
						Criterions: nil,
					},
					Severity: "Important",
					Cve:      "CVE-2018-6148",
				},
			},
			putAdvisoryList: []putAdvisory{
				{
					input: putAdvisoryInput{
						source:   "OpenSUSE Leap 15.0",
						pkgName:  "opera",
						cveID:    "CVE-2018-6148",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "54.0.2952.41-lp150.2.3"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "OpenSUSE Leap 15.0",
						pkgName:  "chromedriver",
						cveID:    "CVE-2018-6148",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "67.0.3396.99-lp150.2.3"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "OpenSUSE Leap 15.0",
						pkgName:  "chromium",
						cveID:    "CVE-2018-6148",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "67.0.3396.99-lp150.2.3"},
					},
				},
			},
			putVulnerabilityDetailList: []putVulnerabilityDetail{
				{
					input: putVulnerabilityDetailInput{
						cveID:  "CVE-2018-6148",
						source: vulnerability.SuseOVAL,
						vuln: types.VulnerabilityDetail{
							Description: "Incorrect implementation in Content Security Policy in Google Chrome prior to 67.0.3396.79 allowed a remote attacker to bypass navigation restrictions via a crafted HTML page.",
							References: []string{
								"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6148",
							},
							Title:    "CVE-2018-6148",
							Severity: types.SeverityHigh,
						},
					},
				},
			},
			putSeverityList: []putSeverity{
				{
					input: putSeverityInput{
						cveID:    "CVE-2018-6148",
						severity: types.SeverityUnknown,
					},
				},
			},
		},
		{
			name: "SUSE Linux Enterprise Server 12 happy path 'package first criteria' json",
			cves: []SuseOVAL{
				{
					Title:       "CVE-2014-1624",
					Description: "Race condition in the xdg.BaseDirectory.get_runtime_dir function in python-xdg 0.25 allows local users to overwrite arbitrary files by pre-creating /tmp/pyxdg-runtime-dir-fallback-victim to point to a victim-owned location, then replacing it with a symlink to an attacker-controlled location once the get_runtime_dir function is called.",
					Platform: []string{
						"SUSE Linux Enterprise Server 12 SP3-TERADATA",
						"SUSE Linux Enterprise Server 12 SP4",
						"SUSE Linux Enterprise Server 12 SP5",
						"SUSE Linux Enterprise Server for SAP Applications 12 SP3-TERADATA",
						"SUSE Linux Enterprise Server for SAP Applications 12 SP4",
						"SUSE Linux Enterprise Server for SAP Applications 12 SP5",
					},
					References: []Reference{
						{
							Source: "CVE",
							URI:    "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-1624",
							ID:     "CVE-2014-1624",
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
										Comment: "SUSE Linux Enterprise Server 12 SP3-TERADATA is installed",
									},
									{
										Comment: "SUSE Linux Enterprise Server 12 SP4 is installed",
									},
									{
										Comment: "SUSE Linux Enterprise Server 12 SP5 is installed",
									},
								},
							},
						},
						Criterions: []Criterion{
							{
								Comment: "python-xdg-0.25-9.3 is installed",
							},
						},
					},
					Severity: "Low",
					Cve:      "CVE-2014-1624",
				},
			},
			putAdvisoryList: []putAdvisory{
				{
					input: putAdvisoryInput{
						source:   "SUSE Linux Enterprise 12.3",
						pkgName:  "python-xdg",
						cveID:    "CVE-2014-1624",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "0.25-9.3"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "SUSE Linux Enterprise 12.4",
						pkgName:  "python-xdg",
						cveID:    "CVE-2014-1624",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "0.25-9.3"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "SUSE Linux Enterprise 12.5",
						pkgName:  "python-xdg",
						cveID:    "CVE-2014-1624",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "0.25-9.3"},
					},
				},
			},
			putVulnerabilityDetailList: []putVulnerabilityDetail{
				{
					input: putVulnerabilityDetailInput{
						cveID:  "CVE-2014-1624",
						source: vulnerability.SuseOVAL,
						vuln: types.VulnerabilityDetail{
							Description: "Race condition in the xdg.BaseDirectory.get_runtime_dir function in python-xdg 0.25 allows local users to overwrite arbitrary files by pre-creating /tmp/pyxdg-runtime-dir-fallback-victim to point to a victim-owned location, then replacing it with a symlink to an attacker-controlled location once the get_runtime_dir function is called.",
							References: []string{
								"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-1624",
							},
							Title:    "CVE-2014-1624",
							Severity: types.SeverityLow,
						},
					},
				},
			},
			putSeverityList: []putSeverity{
				{
					input: putSeverityInput{
						cveID:    "CVE-2014-1624",
						severity: types.SeverityUnknown,
					},
				},
			},
		},
		{
			name: "SUSE Linux Enterprise Server 12 happy path 'osinfo first criteria' json",
			cves: []SuseOVAL{
				{
					Title:       "CVE-2019-0154",
					Description: "Insufficient access control in subsystem for Intel (R) processor graphics in 6th, 7th, 8th and 9th Generation Intel(R) Core(TM) Processor Families; Intel(R) Pentium(R) Processor J, N, Silver and Gold Series; Intel(R) Celeron(R) Processor J, N, G3900 and G4900 Series; Intel(R) Atom(R) Processor A and E3900 Series; Intel(R) Xeon(R) Processor E3-1500 v5 and v6 and E-2100 Processor Families may allow an authenticated user to potentially enable denial of service via local access.",
					Platform: []string{
						"SUSE Linux Enterprise Server 12 SP2-BCL",
						"SUSE Linux Enterprise Server 12 SP2-ESPOS",
						"SUSE Linux Enterprise Server 12 SP2-LTSS",
						"SUSE Linux Enterprise Server 12 SP3-BCL",
						"SUSE Linux Enterprise Server 12 SP3-ESPOS",
						"SUSE Linux Enterprise Server 12 SP3-LTSS",
						"SUSE Linux Enterprise Server 12 SP4",
						"SUSE Linux Enterprise Server for SAP Applications 12 SP2",
						"SUSE Linux Enterprise Server for SAP Applications 12 SP2-BCL",
						"SUSE Linux Enterprise Server for SAP Applications 12 SP2-ESPOS",
						"SUSE Linux Enterprise Server for SAP Applications 12 SP2-LTSS",
						"SUSE Linux Enterprise Server for SAP Applications 12 SP3",
						"SUSE Linux Enterprise Server for SAP Applications 12 SP3-BCL",
						"SUSE Linux Enterprise Server for SAP Applications 12 SP3-ESPOS",
						"SUSE Linux Enterprise Server for SAP Applications 12 SP3-LTSS",
						"SUSE Linux Enterprise Server for SAP Applications 12 SP4",
						"SUSE Linux Enterprise Workstation Extension 12 SP4",
					},
					References: []Reference{
						{
							Source: "CVE",
							URI:    "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-0154",
							ID:     "CVE-2019-0154",
						},
					},
					Criteria: Criteria{
						Operator: "OR",
						Criterias: []Criteria{
							{
								Operator: "AND",
								Criterias: []Criteria{
									{
										Operator:  "OR",
										Criterias: nil,
										Criterions: []Criterion{
											{
												Comment: "kernel-default-4.12.14-95.40 is installed",
											},
											{
												Comment: "kernel-default-extra-4.12.14-95.40 is installed",
											},
										},
									},
								},
								Criterions: []Criterion{
									{
										Comment: "SUSE Linux Enterprise Workstation Extension 12 SP4 is installed",
									},
								},
							},
							{
								Operator: "AND",
								Criterias: []Criteria{
									{
										Operator:  "OR",
										Criterias: nil,
										Criterions: []Criterion{
											{
												Comment: "SUSE Linux Enterprise Server 12 SP4 is installed",
											},
											{
												Comment: "SUSE Linux Enterprise Server for SAP Applications 12 SP4 is installed",
											},
										},
									},
									{
										Operator:  "OR",
										Criterias: nil,
										Criterions: []Criterion{
											{
												Comment: "kernel-default-base-4.12.14-95.40 is installed",
											},
											{
												Comment: "kernel-default-devel-4.12.14-95.40 is installed",
											},
										},
									},
								},
								Criterions: nil,
							},
							{
								Operator: "AND",
								Criterias: []Criteria{
									{
										Operator:  "OR",
										Criterias: nil,
										Criterions: []Criterion{
											{
												Comment: "SUSE Linux Enterprise Server 12 SP3-ESPOS is installed",
											},
											{
												Comment: "SUSE Linux Enterprise Server for SAP Applications 12 SP3 is installed",
											},
										},
									},
									{
										Operator:  "OR",
										Criterias: nil,
										Criterions: []Criterion{
											{
												Comment: "kernel-macros-4.4.180-94.107 is installed",
											},
											{
												Comment: "kernel-source-4.4.180-94.107 is installed",
											},
										},
									},
								},
								Criterions: nil,
							},
						},
						Criterions: nil,
					},
					Severity: "Important",
					Cve:      "CVE-2019-0154",
				},
			},
			putAdvisoryList: []putAdvisory{
				{
					input: putAdvisoryInput{
						source:   "SUSE Linux Enterprise 12.4",
						pkgName:  "kernel-default",
						cveID:    "CVE-2019-0154",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "4.12.14-95.40"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "SUSE Linux Enterprise 12.4",
						pkgName:  "kernel-default-extra",
						cveID:    "CVE-2019-0154",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "4.12.14-95.40"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "SUSE Linux Enterprise 12.4",
						pkgName:  "kernel-default-base",
						cveID:    "CVE-2019-0154",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "4.12.14-95.40"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "SUSE Linux Enterprise 12.4",
						pkgName:  "kernel-default-devel",
						cveID:    "CVE-2019-0154",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "4.12.14-95.40"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "SUSE Linux Enterprise 12.3",
						pkgName:  "kernel-macros",
						cveID:    "CVE-2019-0154",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "4.4.180-94.107"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "SUSE Linux Enterprise 12.3",
						pkgName:  "kernel-source",
						cveID:    "CVE-2019-0154",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "4.4.180-94.107"},
					},
				},
			},
			putVulnerabilityDetailList: []putVulnerabilityDetail{
				{
					input: putVulnerabilityDetailInput{
						cveID:  "CVE-2019-0154",
						source: vulnerability.SuseOVAL,
						vuln: types.VulnerabilityDetail{
							Description: "Insufficient access control in subsystem for Intel (R) processor graphics in 6th, 7th, 8th and 9th Generation Intel(R) Core(TM) Processor Families; Intel(R) Pentium(R) Processor J, N, Silver and Gold Series; Intel(R) Celeron(R) Processor J, N, G3900 and G4900 Series; Intel(R) Atom(R) Processor A and E3900 Series; Intel(R) Xeon(R) Processor E3-1500 v5 and v6 and E-2100 Processor Families may allow an authenticated user to potentially enable denial of service via local access.",
							References: []string{
								"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-0154",
							},
							Title:    "CVE-2019-0154",
							Severity: types.SeverityHigh,
						},
					},
				},
			},
			putSeverityList: []putSeverity{
				{
					input: putSeverityInput{
						cveID:    "CVE-2019-0154",
						severity: types.SeverityUnknown,
					},
				},
			},
		},
		{
			name: "SUSE Linux Enterprise Server 12 happy path 'OR AND OR operator' json",
			cves: []SuseOVAL{
				{
					Title:       "CVE-2019-11728",
					Description: "The HTTP Alternative Services header, Alt-Svc, can be used by a malicious site to scan all TCP ports of any host that the accessible to a user when web content is loaded. This vulnerability affects Firefox \u003c 68.",
					Platform: []string{
						"SUSE Linux Enterprise Server 12 SP1-LTSS",
						"SUSE Linux Enterprise Server 12 SP2-BCL",
						"SUSE Linux Enterprise Server 12 SP2-ESPOS",
						"SUSE Linux Enterprise Server 12 SP2-LTSS",
						"SUSE Linux Enterprise Server 12 SP3-BCL",
						"SUSE Linux Enterprise Server 12 SP3-ESPOS",
						"SUSE Linux Enterprise Server 12 SP3-LTSS",
						"SUSE Linux Enterprise Server 12 SP3-TERADATA",
						"SUSE Linux Enterprise Server 12 SP4",
						"SUSE Linux Enterprise Server 12 SP5",
						"SUSE Linux Enterprise Server for SAP Applications 12 SP1",
						"SUSE Linux Enterprise Server for SAP Applications 12 SP1-LTSS",
						"SUSE Linux Enterprise Server for SAP Applications 12 SP2",
						"SUSE Linux Enterprise Server for SAP Applications 12 SP2-BCL",
						"SUSE Linux Enterprise Server for SAP Applications 12 SP2-ESPOS",
						"SUSE Linux Enterprise Server for SAP Applications 12 SP2-LTSS",
						"SUSE Linux Enterprise Server for SAP Applications 12 SP3",
						"SUSE Linux Enterprise Server for SAP Applications 12 SP3-BCL",
						"SUSE Linux Enterprise Server for SAP Applications 12 SP3-ESPOS",
						"SUSE Linux Enterprise Server for SAP Applications 12 SP3-LTSS",
						"SUSE Linux Enterprise Server for SAP Applications 12 SP3-TERADATA",
						"SUSE Linux Enterprise Server for SAP Applications 12 SP4",
						"SUSE Linux Enterprise Server for SAP Applications 12 SP5",
					},
					References: []Reference{
						{
							Source: "CVE",
							URI:    "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11728",
							ID:     "CVE-2019-11728",
						},
					},
					Criteria: Criteria{
						Operator: "OR",
						Criterias: []Criteria{
							{
								Operator: "AND",
								Criterias: []Criteria{
									{
										Operator:  "OR",
										Criterias: nil,
										Criterions: []Criterion{
											{
												Comment: "SUSE Linux Enterprise Server 12 SP3-ESPOS is installed",
											},
											{
												Comment: "SUSE Linux Enterprise Server for SAP Applications 12 SP4 is installed",
											},
										},
									},
									{
										Operator:  "OR",
										Criterias: nil,
										Criterions: []Criterion{
											{
												Comment: "MozillaFirefox-68.1.0-109.89 is installed",
											},
											{
												Comment: "MozillaFirefox-branding-SLE-68-32.8 is installed",
											},
											{
												Comment: "MozillaFirefox-translations-common-68.1.0-109.89 is installed",
											},
										},
									},
								},
								Criterions: nil,
							},
						},
						Criterions: nil,
					},
					Severity: "Important",
					Cve:      "CVE-2019-11728",
				},
			},
			putAdvisoryList: []putAdvisory{
				{
					input: putAdvisoryInput{
						source:   "SUSE Linux Enterprise 12.3",
						pkgName:  "MozillaFirefox",
						cveID:    "CVE-2019-11728",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "68.1.0-109.89"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "SUSE Linux Enterprise 12.3",
						pkgName:  "MozillaFirefox-branding-SLE",
						cveID:    "CVE-2019-11728",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "68-32.8"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "SUSE Linux Enterprise 12.3",
						pkgName:  "MozillaFirefox-translations-common",
						cveID:    "CVE-2019-11728",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "68.1.0-109.89"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "SUSE Linux Enterprise 12.4",
						pkgName:  "MozillaFirefox",
						cveID:    "CVE-2019-11728",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "68.1.0-109.89"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "SUSE Linux Enterprise 12.4",
						pkgName:  "MozillaFirefox-branding-SLE",
						cveID:    "CVE-2019-11728",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "68-32.8"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "SUSE Linux Enterprise 12.4",
						pkgName:  "MozillaFirefox-translations-common",
						cveID:    "CVE-2019-11728",
						advisory: types.Advisory{VulnerabilityID: "", FixedVersion: "68.1.0-109.89"},
					},
				},
			},
			putVulnerabilityDetailList: []putVulnerabilityDetail{
				{
					input: putVulnerabilityDetailInput{
						cveID:  "CVE-2019-11728",
						source: vulnerability.SuseOVAL,
						vuln: types.VulnerabilityDetail{
							Description: "The HTTP Alternative Services header, Alt-Svc, can be used by a malicious site to scan all TCP ports of any host that the accessible to a user when web content is loaded. This vulnerability affects Firefox \u003c 68.",
							References: []string{
								"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11728",
							},
							Title:    "CVE-2019-11728",
							Severity: types.SeverityHigh,
						},
					},
				},
			},
			putSeverityList: []putSeverity{
				{
					input: putSeverityInput{
						cveID:    "CVE-2019-11728",
						severity: types.SeverityUnknown,
					},
				},
			},
		},
		{
			name: "SUSE Enterprise Server happy path 'criteria empty' json",
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
			name: "suse GetAdvisories return an error",
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
