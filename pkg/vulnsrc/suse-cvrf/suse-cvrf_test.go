package susecvrf

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
)

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func TestVulnSrc_Update(t *testing.T) {
	testCases := []struct {
		name           string
		dist           Distribution
		cacheDir       string
		batchUpdateErr error
		expectedError  error
	}{
		{
			name:     "happy path with SUSE Enterprise Linux",
			dist:     SUSEEnterpriseLinux,
			cacheDir: "testdata",
		},
		{
			name:     "happy path with openSUSE",
			dist:     OpenSUSE,
			cacheDir: "testdata",
		},
		{
			name:          "cache dir doesnt exist",
			dist:          SUSEEnterpriseLinux,
			cacheDir:      "badpathdoesnotexist",
			expectedError: errors.New("error in SUSE CVRF walk: error in file walk: lstat badpathdoesnotexist/vuln-list/cvrf/suse/suse: no such file or directory"),
		},
		{
			name:           "unable to save suse linux oval defintions",
			dist:           SUSEEnterpriseLinux,
			cacheDir:       "testdata",
			batchUpdateErr: errors.New("unable to batch update"),
			expectedError:  errors.New("error in SUSE CVRF save: error in batch update: unable to batch update"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDBConfig := new(db.MockOperation)
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
	testCases := []struct {
		name                   string
		cvrfs                  []SuseCvrf
		putAdvisoryDetail      []db.OperationPutAdvisoryDetailExpectation
		putVulnerabilityDetail []db.OperationPutVulnerabilityDetailExpectation
		putSeverity            []db.OperationPutSeverityExpectation
		expectedErrorMsg       string
	}{
		{
			name: "happy path with SUSE Enterprise Linux",
			cvrfs: []SuseCvrf{
				{
					Title: "Security update for helm-mirror",
					Tracking: DocumentTracking{
						ID: "SUSE-SU-2019:0048-2",
					},
					Notes: []DocumentNote{
						{
							Text:  "Security update for helm-mirror",
							Title: "Topic",
							Type:  "Summary",
						},
						{
							Text:  "This update for helm-mirror to version 0.2.1 fixes the following issues:\n\n\nSecurity issues fixed:\n\n- CVE-2018-16873: Fixed a remote command execution (bsc#1118897)\n- CVE-2018-16874: Fixed a directory traversal in \u0026quot;go get\u0026quot; via curly braces in import path (bsc#1118898)\n- CVE-2018-16875: Fixed a CPU denial of service (bsc#1118899)\n\nNon-security issue fixed:\n\n- Update to v0.2.1 (bsc#1120762)\n- Include helm-mirror into the containers module (bsc#1116182)\n",
							Title: "Details",
							Type:  "General",
						},
						{
							Text:  "The CVRF data is provided by SUSE under the Creative Commons License 4.0 with Attribution for Non-Commercial usage (CC-BY-NC-4.0).",
							Title: "Terms of Use",
							Type:  "Legal Disclaimer",
						},
					},
					ProductTree: ProductTree{
						Relationships: []Relationship{
							{
								ProductReference:          "helm-mirror-0.2.1-1.7.1",
								RelatesToProductReference: "SUSE Linux Enterprise Module for Containers 15 SP1",
								RelationType:              "Default Component Of",
							},
						},
					},
					References: []Reference{
						{
							URL:         "https://www.suse.com/support/update/announcement/2019/suse-su-20190048-2/",
							Description: "Link for SUSE-SU-2019:0048-2",
						},
						{
							URL:         "http://lists.suse.com/pipermail/sle-security-updates/2019-July/005660.html",
							Description: "E-Mail link for SUSE-SU-2019:0048-2",
						},
					},
					Vulnerabilities: []Vulnerability{
						{
							CVE: "CVE-2018-16873",
							Threats: []Threat{
								{
									Type:     "Impact",
									Severity: "important",
								},
							},
						},
						{
							CVE: "CVE-2018-16874",
							Threats: []Threat{
								{
									Type:     "Impact",
									Severity: "moderate",
								},
							},
						},
						{
							CVE: "CVE-2018-16875",
							Threats: []Threat{
								{
									Type:     "Impact",
									Severity: "moderate",
								},
							},
						},
					},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "SUSE Linux Enterprise 15.1",
						PkgName:         "helm-mirror",
						VulnerabilityID: "SUSE-SU-2019:0048-2",
						Advisory: types.Advisory{
							FixedVersion: "0.2.1-1.7.1",
						},
					},
					Returns: db.OperationPutAdvisoryDetailReturns{},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:      true,
						VulnerabilityID: "SUSE-SU-2019:0048-2",
						Source:          "suse-cvrf",
						Vulnerability: types.VulnerabilityDetail{
							Title:       "Security update for helm-mirror",
							Description: "This update for helm-mirror to version 0.2.1 fixes the following issues:\n\n\nSecurity issues fixed:\n\n- CVE-2018-16873: Fixed a remote command execution (bsc#1118897)\n- CVE-2018-16874: Fixed a directory traversal in \u0026quot;go get\u0026quot; via curly braces in import path (bsc#1118898)\n- CVE-2018-16875: Fixed a CPU denial of service (bsc#1118899)\n\nNon-security issue fixed:\n\n- Update to v0.2.1 (bsc#1120762)\n- Include helm-mirror into the containers module (bsc#1116182)\n",
							References: []string{
								"https://www.suse.com/support/update/announcement/2019/suse-su-20190048-2/",
								"http://lists.suse.com/pipermail/sle-security-updates/2019-July/005660.html",
							},
							Severity: types.SeverityHigh,
						},
					},
					Returns: db.OperationPutVulnerabilityDetailReturns{},
				},
			},
			putSeverity: []db.OperationPutSeverityExpectation{
				{
					Args: db.OperationPutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "SUSE-SU-2019:0048-2",
						Severity:        types.SeverityUnknown,
					},
				},
			},
		},
		{
			name: "happy path with openSUSE",
			cvrfs: []SuseCvrf{
				{
					Title: "Security update for strongswan",
					Tracking: DocumentTracking{
						ID: "openSUSE-SU-2019:2598-1",
					},
					Notes: []DocumentNote{
						{
							Text:  "Security update for GraphicsMagick",
							Title: "Topic",
							Type:  "Summary",
						},
						{
							Text:  "This update for GraphicsMagick fixes the following issues:\n\nSecurity vulnerabilities fixed:\n\n- CVE-2018-20184: Fixed heap-based buffer overflow in the WriteTGAImage function of tga.c (bsc#1119822)\n- CVE-2018-20189: Fixed denial of service vulnerability in ReadDIBImage function of coders/dib.c (bsc#1119790)\n\nThis update was imported from the openSUSE:Leap:15.0:Update update project.",
							Title: "Details",
							Type:  "General",
						},
						{
							Text:  "The CVRF data is provided by SUSE under the Creative Commons License 4.0 with Attribution for Non-Commercial usage (CC-BY-NC-4.0).",
							Title: "Terms of Use",
							Type:  "Legal Disclaimer",
						},
					},
					ProductTree: ProductTree{
						Relationships: []Relationship{
							{
								ProductReference:          "strongswan-5.6.0-lp151.4.3.1",
								RelatesToProductReference: "openSUSE Leap 15.1",
								RelationType:              "Default Component Of",
							},
							{
								ProductReference:          "strongswan-sqlite-5.6.0-lp151.4.3.1",
								RelatesToProductReference: "openSUSE Leap 15.1",
								RelationType:              "Default Component Of",
							},
						},
					},
					References: []Reference{
						{
							URL:         "http://lists.opensuse.org/opensuse-security-announce/2019-12/msg00001.html",
							Description: "E-Mail link for openSUSE-SU-2019:2598-1",
						},
						{
							URL:         "https://www.suse.com/support/security/rating/",
							Description: "SUSE Security Ratings",
						},
					},
					Vulnerabilities: []Vulnerability{
						{
							CVE:         "CVE-2018-10811",
							Description: "strongSwan 5.6.0 and older allows Remote Denial of Service because of Missing Initialization of a Variable.",
							Threats:     []Threat{{Type: "Impact", Severity: "important"}},
						},
						{
							CVE:         "CVE-2018-16151",
							Description: "In verify_emsa_pkcs1_signature() in gmp_rsa_public_key.c in the gmp plugin in strongSwan 4.x and 5.x before 5.7.0, the RSA implementation based on GMP does not reject excess data after the encoded algorithm OID during PKCS#1 v1.5 signature verification. Similar to the flaw in the same version of strongSwan regarding digestAlgorithm.parameters, a remote attacker can forge signatures when small public exponents are being used, which could lead to impersonation when only an RSA signature is used for IKEv2 authentication.",
							Threats:     []Threat{{Type: "Impact", Severity: "moderate"}},
						},
						{
							CVE:         "CVE-2018-16152",
							Description: "In verify_emsa_pkcs1_signature() in gmp_rsa_public_key.c in the gmp plugin in strongSwan 4.x and 5.x before 5.7.0, the RSA implementation based on GMP does not reject excess data in the digestAlgorithm.parameters field during PKCS#1 v1.5 signature verification. Consequently, a remote attacker can forge signatures when small public exponents are being used, which could lead to impersonation when only an RSA signature is used for IKEv2 authentication. This is a variant of CVE-2006-4790 and CVE-2014-1568.",
							Threats:     []Threat{{Type: "Impact", Severity: "moderate"}},
						},
						{
							CVE:         "CVE-2018-17540",
							Description: "The gmp plugin in strongSwan before 5.7.1 has a Buffer Overflow via a crafted certificate.",
							Threats:     []Threat{{Type: "Impact", Severity: "important"}},
						},
					},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "openSUSE Leap 15.1",
						PkgName:         "strongswan",
						VulnerabilityID: "openSUSE-SU-2019:2598-1",
						Advisory: types.Advisory{
							FixedVersion: "5.6.0-lp151.4.3.1",
						},
					},
					Returns: db.OperationPutAdvisoryDetailReturns{},
				},
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "openSUSE Leap 15.1",
						PkgName:         "strongswan-sqlite",
						VulnerabilityID: "openSUSE-SU-2019:2598-1",
						Advisory: types.Advisory{
							FixedVersion: "5.6.0-lp151.4.3.1",
						},
					},
					Returns: db.OperationPutAdvisoryDetailReturns{},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:      true,
						VulnerabilityID: "openSUSE-SU-2019:2598-1",
						Source:          "suse-cvrf",
						Vulnerability: types.VulnerabilityDetail{
							Title:       "Security update for strongswan",
							Description: "This update for GraphicsMagick fixes the following issues:\n\nSecurity vulnerabilities fixed:\n\n- CVE-2018-20184: Fixed heap-based buffer overflow in the WriteTGAImage function of tga.c (bsc#1119822)\n- CVE-2018-20189: Fixed denial of service vulnerability in ReadDIBImage function of coders/dib.c (bsc#1119790)\n\nThis update was imported from the openSUSE:Leap:15.0:Update update project.",
							References: []string{
								"http://lists.opensuse.org/opensuse-security-announce/2019-12/msg00001.html",
								"https://www.suse.com/support/security/rating/",
							},
							Severity: types.SeverityHigh,
						},
					},
					Returns: db.OperationPutVulnerabilityDetailReturns{},
				},
			},
			putSeverity: []db.OperationPutSeverityExpectation{
				{
					Args: db.OperationPutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "openSUSE-SU-2019:2598-1",
						Severity:        types.SeverityUnknown,
					},
				},
			},
		},
		{
			name: "happy path with openSUSE CVRF including SUSE Linux Enterprise Linux",
			cvrfs: []SuseCvrf{
				{
					Title: "Security update for GraphicsMagick",
					Tracking: DocumentTracking{
						ID: "openSUSE-SU-2019:0003-1",
					},
					ProductTree: ProductTree{
						Relationships: []Relationship{
							{
								ProductReference:          "GraphicsMagick-1.3.29-bp150.2.12.1",
								RelatesToProductReference: "SUSE Package Hub for SUSE Linux Enterprise 15",
								RelationType:              "Default Component Of",
							},
							{
								ProductReference:          "GraphicsMagick-devel-1.3.29-bp150.2.12.1",
								RelatesToProductReference: "SUSE Package Hub for SUSE Linux Enterprise 15",
								RelationType:              "Default Component Of",
							},
						},
					},
					References: []Reference{
						{
							URL:         "http://lists.opensuse.org/opensuse-security-announce/2019-01/msg00001.html",
							Description: "E-Mail link for openSUSE-SU-2019:0003-1",
						},
						{
							URL:         "https://www.suse.com/support/security/rating/",
							Description: "SUSE Security Ratings",
						},
					},
					Vulnerabilities: []Vulnerability{
						{
							CVE: "CVE-2018-20184",
							Threats: []Threat{
								{
									Type:     "Impact",
									Severity: "moderate",
								},
							},
						},
						{
							CVE:         "CVE-2018-20189",
							Description: "In GraphicsMagick 1.3.31, the ReadDIBImage function of coders/dib.c has a vulnerability allowing a crash and denial of service via a dib file that is crafted to appear with direct pixel values and also colormapping (which is not available beyond 8-bits/sample), and therefore lacks indexes initialization.",
							Threats: []Threat{
								{
									Type:     "Impact",
									Severity: "low",
								},
							},
						},
					},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "SUSE Linux Enterprise 15",
						PkgName:         "GraphicsMagick",
						VulnerabilityID: "openSUSE-SU-2019:0003-1",
						Advisory: types.Advisory{
							FixedVersion: "1.3.29-bp150.2.12.1",
						},
					},
					Returns: db.OperationPutAdvisoryDetailReturns{},
				},
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "SUSE Linux Enterprise 15",
						PkgName:         "GraphicsMagick-devel",
						VulnerabilityID: "openSUSE-SU-2019:0003-1",
						Advisory: types.Advisory{
							FixedVersion: "1.3.29-bp150.2.12.1",
						},
					},
					Returns: db.OperationPutAdvisoryDetailReturns{},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:      true,
						VulnerabilityID: "openSUSE-SU-2019:0003-1",
						Source:          "suse-cvrf",
						Vulnerability: types.VulnerabilityDetail{
							Title: "Security update for GraphicsMagick",
							References: []string{
								"http://lists.opensuse.org/opensuse-security-announce/2019-01/msg00001.html",
								"https://www.suse.com/support/security/rating/",
							},
							Severity: types.SeverityMedium,
						},
					},
					Returns: db.OperationPutVulnerabilityDetailReturns{},
				},
			},
			putSeverity: []db.OperationPutSeverityExpectation{
				{
					Args: db.OperationPutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "openSUSE-SU-2019:0003-1",
						Severity:        types.SeverityUnknown,
					},
				},
			},
		},
		{
			name: "PutAdvisory returns an error",
			cvrfs: []SuseCvrf{
				{
					Title: "Security update for GraphicsMagick",
					Tracking: DocumentTracking{
						ID: "openSUSE-SU-2019:0003-1",
					},
					ProductTree: ProductTree{
						Relationships: []Relationship{
							{
								ProductReference:          "GraphicsMagick-1.3.29-bp150.2.12.1",
								RelatesToProductReference: "SUSE Package Hub for SUSE Linux Enterprise 15",
								RelationType:              "Default Component Of",
							},
						},
					},
					Vulnerabilities: []Vulnerability{
						{
							CVE:     "CVE-2018-20184",
							Threats: []Threat{{Type: "Impact", Severity: "moderate"}},
						},
					},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:              true,
						SourceAnything:          true,
						PkgNameAnything:         true,
						VulnerabilityIDAnything: true,
						AdvisoryAnything:        true,
					},
					Returns: db.OperationPutAdvisoryDetailReturns{
						Err: errors.New("error"),
					},
				},
			},
			expectedErrorMsg: "unable to save SUSE Linux Enterprise 15 CVRF",
		},
		{
			name: "PutVulnerabilityDetail returns an error",
			cvrfs: []SuseCvrf{
				{
					Title: "Security update for GraphicsMagick",
					Tracking: DocumentTracking{
						ID: "openSUSE-SU-2019:0003-1",
					},
					ProductTree: ProductTree{
						Relationships: []Relationship{
							{
								ProductReference:          "GraphicsMagick-1.3.29-bp150.2.12.1",
								RelatesToProductReference: "SUSE Package Hub for SUSE Linux Enterprise 15",
								RelationType:              "Default Component Of",
							},
						},
					},
					Vulnerabilities: []Vulnerability{
						{
							CVE:     "CVE-2018-20184",
							Threats: []Threat{{Type: "Impact", Severity: "moderate"}},
						},
					},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:              true,
						SourceAnything:          true,
						PkgNameAnything:         true,
						VulnerabilityIDAnything: true,
						AdvisoryAnything:        true,
					},
					Returns: db.OperationPutAdvisoryDetailReturns{},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:              true,
						VulnerabilityIDAnything: true,
						SourceAnything:          true,
						VulnerabilityAnything:   true,
					},
					Returns: db.OperationPutVulnerabilityDetailReturns{
						Err: errors.New("error"),
					},
				},
			},
			expectedErrorMsg: "failed to save SUSE CVRF vulnerability",
		},
		{
			name: "PutSeverity returns an error",
			cvrfs: []SuseCvrf{
				{
					Title: "Security update for GraphicsMagick",
					Tracking: DocumentTracking{
						ID: "openSUSE-SU-2019:0003-1",
					},
					ProductTree: ProductTree{
						Relationships: []Relationship{
							{
								ProductReference:          "GraphicsMagick-1.3.29-bp150.2.12.1",
								RelatesToProductReference: "SUSE Package Hub for SUSE Linux Enterprise 15",
								RelationType:              "Default Component Of",
							},
						},
					},
					Vulnerabilities: []Vulnerability{
						{
							CVE:     "CVE-2018-20184",
							Threats: []Threat{{Type: "Impact", Severity: "moderate"}},
						},
					},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:              true,
						SourceAnything:          true,
						PkgNameAnything:         true,
						VulnerabilityIDAnything: true,
						AdvisoryAnything:        true,
					},
					Returns: db.OperationPutAdvisoryDetailReturns{},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:              true,
						VulnerabilityIDAnything: true,
						SourceAnything:          true,
						VulnerabilityAnything:   true,
					},
					Returns: db.OperationPutVulnerabilityDetailReturns{},
				},
			},
			putSeverity: []db.OperationPutSeverityExpectation{
				{
					Args: db.OperationPutSeverityArgs{
						TxAnything:              true,
						VulnerabilityIDAnything: true,
						SeverityAnything:        true,
					},
					Returns: db.OperationPutSeverityReturns{
						Err: errors.New("error"),
					},
				},
			},
			expectedErrorMsg: "failed to save SUSE vulnerability severity",
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
			err := ac.commit(tx, tc.cvrfs)

			switch {
			case tc.expectedErrorMsg != "":
				require.NotNil(t, err, tc.name)
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
		name          string
		version       string
		pkgName       string
		dist          Distribution
		getAdvisories db.OperationGetAdvisoriesExpectation
		expectedError string
		expectedVulns []types.Advisory
	}{
		{
			name:    "happy path with openSUSE",
			version: "13.1",
			pkgName: "bind",
			dist:    OpenSUSE,
			getAdvisories: db.OperationGetAdvisoriesExpectation{
				Args: db.OperationGetAdvisoriesArgs{
					Source:  "openSUSE Leap 13.1",
					PkgName: "bind",
				},
				Returns: db.OperationGetAdvisoriesReturns{
					Advisories: []types.Advisory{
						{
							VulnerabilityID: "openSUSE-SU-2019:0003-1",
							FixedVersion:    "1.3.29-bp150.2.12.1",
						},
					},
				},
			},
			expectedVulns: []types.Advisory{
				{
					VulnerabilityID: "openSUSE-SU-2019:0003-1",
					FixedVersion:    "1.3.29-bp150.2.12.1",
				},
			},
		},
		{
			name:    "GetAdvisories returns an error",
			version: "15.1",
			pkgName: "bind",
			dist:    SUSEEnterpriseLinux,
			getAdvisories: db.OperationGetAdvisoriesExpectation{
				Args: db.OperationGetAdvisoriesArgs{
					SourceAnything:  true,
					PkgNameAnything: true,
				},
				Returns: db.OperationGetAdvisoriesReturns{
					Err: errors.New("error"),
				},
			},
			expectedError: "failed to get SUSE advisories",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDBConfig := new(db.MockOperation)
			mockDBConfig.ApplyGetAdvisoriesExpectation(tc.getAdvisories)

			ac := VulnSrc{dist: tc.dist, dbc: mockDBConfig}
			vuls, err := ac.Get(tc.version, tc.pkgName)

			switch {
			case tc.expectedError != "":
				require.NotNil(t, err, tc.name)
				assert.Contains(t, err.Error(), tc.expectedError, tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}
			assert.Equal(t, tc.expectedVulns, vuls, tc.name)

			mockDBConfig.AssertExpectations(t)
		})
	}
}

func TestSeverityFromThreat(t *testing.T) {
	testCases := map[string]types.Severity{
		"low":       types.SeverityLow,
		"moderate":  types.SeverityMedium,
		"important": types.SeverityHigh,
		"critical":  types.SeverityCritical,
		"":          types.SeverityUnknown,
		"invalid":   types.SeverityUnknown,
	}
	for k, v := range testCases {
		assert.Equal(t, v, severityFromThreat(k))
	}
}

func TestGetOSVersion(t *testing.T) {
	testCases := []struct {
		inputPlatformName    string
		expectedPlatformName string
	}{

		{
			inputPlatformName:    "SUSE Linux Enterprise Workstation Extension 12 SP4",
			expectedPlatformName: "SUSE Linux Enterprise 12.4",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Module for Basesystem 15 SP1",
			expectedPlatformName: "SUSE Linux Enterprise 15.1",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server for SAP Applications 12 SP3-LTSS",
			expectedPlatformName: "SUSE Linux Enterprise 12.3",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Module for Containers 12",
			expectedPlatformName: "SUSE Linux Enterprise 12",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise High Availability 12 SP1",
			expectedPlatformName: "SUSE Linux Enterprise 12.1",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server for SAP Applications 12 SP1-LTSS",
			expectedPlatformName: "SUSE Linux Enterprise 12.1",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Module for High Performance Computing 12",
			expectedPlatformName: "SUSE Linux Enterprise 12",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Module for Live Patching 15",
			expectedPlatformName: "SUSE Linux Enterprise 15",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Module for Development Tools 15 SP1",
			expectedPlatformName: "SUSE Linux Enterprise 15.1",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Live Patching 12 SP5",
			expectedPlatformName: "SUSE Linux Enterprise 12.5",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Desktop 11 SP3",
			expectedPlatformName: "SUSE Linux Enterprise 11.3",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Module for Public Cloud 15 SP1",
			expectedPlatformName: "SUSE Linux Enterprise 15.1",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server 11-SECURITY",
			expectedPlatformName: "SUSE Linux Enterprise 11",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server for SAP Applications 11 SP4-CLIENT-TOOLS",
			expectedPlatformName: "SUSE Linux Enterprise 11.4",
		},
		{
			inputPlatformName:    "SUSE Package Hub for SUSE Linux Enterprise 12",
			expectedPlatformName: "SUSE Linux Enterprise 12",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Module for Open Buildservice Development Tools 15",
			expectedPlatformName: "SUSE Linux Enterprise 15",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Desktop 11 SP4",
			expectedPlatformName: "SUSE Linux Enterprise 11.4",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Module for CAP 15 SP1",
			expectedPlatformName: "SUSE Linux Enterprise 15.1",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server 12 SP5",
			expectedPlatformName: "SUSE Linux Enterprise 12.5",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Workstation Extension 15",
			expectedPlatformName: "SUSE Linux Enterprise 15",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Module for additional PackageHub packages 15",
			expectedPlatformName: "SUSE Linux Enterprise 15",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise High Availability 15 SP1",
			expectedPlatformName: "SUSE Linux Enterprise 15.1",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server 12 SP2-LTSS",
			expectedPlatformName: "SUSE Linux Enterprise 12.2",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise High Availability 12",
			expectedPlatformName: "SUSE Linux Enterprise 12",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Real Time Extension 12 SP1",
			expectedPlatformName: "SUSE Linux Enterprise 12.1",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Module for Advanced Systems Management 12",
			expectedPlatformName: "SUSE Linux Enterprise 12",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server 11 SP2-LTSS",
			expectedPlatformName: "SUSE Linux Enterprise 11.2",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server 11-LTSS",
			expectedPlatformName: "SUSE Linux Enterprise 11",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server 11-TERADATA",
			expectedPlatformName: "SUSE Linux Enterprise 11",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Module for Web Scripting 12",
			expectedPlatformName: "SUSE Linux Enterprise 12",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server 12 SP1-LTSS",
			expectedPlatformName: "SUSE Linux Enterprise 12.1",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Live Patching 12 SP3",
			expectedPlatformName: "SUSE Linux Enterprise 12.3",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server 12 SP3-LTSS",
			expectedPlatformName: "SUSE Linux Enterprise 12.3",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server 11 SP4",
			expectedPlatformName: "SUSE Linux Enterprise 11.4",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server for SAP Applications 12 SP2-BCL",
			expectedPlatformName: "SUSE Linux Enterprise 12.2",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Module for Python2 packages 15 SP1",
			expectedPlatformName: "SUSE Linux Enterprise 15.1",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server for SAP Applications 11 SP1-TERADATA",
			expectedPlatformName: "SUSE Linux Enterprise 11.1",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server for SAP Applications 11 SP3-CLIENT-TOOLS",
			expectedPlatformName: "SUSE Linux Enterprise 11.3",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Module for Web Scripting 15",
			expectedPlatformName: "SUSE Linux Enterprise 15",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server 11 SP3-TERADATA",
			expectedPlatformName: "SUSE Linux Enterprise 11.3",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Desktop 12 SP5",
			expectedPlatformName: "SUSE Linux Enterprise 12.5",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server 12 SP2-BCL",
			expectedPlatformName: "SUSE Linux Enterprise 12.2",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Workstation Extension 15 SP1",
			expectedPlatformName: "SUSE Linux Enterprise 15.1",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Software Development Kit 12 SP5",
			expectedPlatformName: "SUSE Linux Enterprise 12.5",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server 12",
			expectedPlatformName: "SUSE Linux Enterprise 12",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server 11 SP3-LTSS",
			expectedPlatformName: "SUSE Linux Enterprise 11.3",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise High Availability 12 SP5",
			expectedPlatformName: "SUSE Linux Enterprise 12.5",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Build System Kit 12",
			expectedPlatformName: "SUSE Linux Enterprise 12",
		},
		{
			inputPlatformName:    "SUSE Cloud Compute Node for SUSE Linux Enterprise 12 5",
			expectedPlatformName: "SUSE Linux Enterprise 12.5",
		},
		{
			inputPlatformName:    "openSUSE Leap 42.3",
			expectedPlatformName: "openSUSE Leap 42.3",
		},
		{
			inputPlatformName:    "openSUSE Leap 42.3 NonFree",
			expectedPlatformName: "openSUSE Leap 42.3",
		},
		{
			inputPlatformName:    "openSUSE Leap 15.1",
			expectedPlatformName: "openSUSE Leap 15.1",
		},
		{
			inputPlatformName:    "openSUSE Leap 15.1 NonFree",
			expectedPlatformName: "openSUSE Leap 15.1",
		},
		// Below tests exclude platformNames
		{
			inputPlatformName:    "openSUSE Leap NonFree 15.1",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Module for SUSE Manager Server 4.0",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "HPE Helion Openstack 8",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "Openstack Cloud Magnum Orchestration 7",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "SUSE CaaS Platform ALL",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "SUSE Enterprise Storage 2.1",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "SUSE Enterprise Storage 6",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "SUSE Lifecycle Management Server 1.3",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "SUSE OpenStack Cloud 6-LTSS",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "SUSE OpenStack Cloud 9",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "SUSE OpenStack Cloud Crowbar 9",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "SUSE Studio Onsite 1.3",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "SUSE Studio Onsite Runner 1.3",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "SUSE WebYast 1.3",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "Subscription Management Tool 11 SP3",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "openSUSE 13.2",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "openSUSE 13.2 NonFree",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "openSUSE Evergreen 11.4",
			expectedPlatformName: "",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.inputPlatformName, func(t *testing.T) {
			actual := getOSVersion(tc.inputPlatformName)
			assert.Equal(t, tc.expectedPlatformName, actual, fmt.Sprintf("input data: %s", tc.inputPlatformName))
		})
	}
}
