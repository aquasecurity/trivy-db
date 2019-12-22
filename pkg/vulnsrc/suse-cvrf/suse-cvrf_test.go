package susecvrf

import (
	"errors"
	"fmt"
	"os"
	"testing"

	bolt "github.com/etcd-io/bbolt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
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
			expectedError: errors.New("error in SUSE CVRF walk: error in file walk: lstat badpathdoesnotexist/vuln-list/cvrf/suse: no such file or directory"),
		},
		{
			name:           "unable to save suse linux oval defintions",
			cacheDir:       "testdata",
			batchUpdateErr: errors.New("unable to batch update"),
			expectedError:  errors.New("error in SUSE CVRF save: error in batch update: unable to batch update"),
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
	testCases := []struct {
		name                   string
		cvrfs                  []SuseCvrf
		putAdvisory            []db.PutAdvisoryExpectation
		putVulnerabilityDetail []db.PutVulnerabilityDetailExpectation
		putSeverity            []db.PutSeverityExpectation
		expectedErrorMsg       string
	}{
		{
			name: "happy path",
			cvrfs: []SuseCvrf{
				{
					Title: "Security update for helm-mirror",
					Tracking: DocumentTracking{
						ID: "SUSE-SU-2019:0048-2",
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
			putAdvisory: []db.PutAdvisoryExpectation{
				{
					Args: db.PutAdvisoryArgs{
						TxAnything:      true,
						Source:          "SUSE Linux Enterprise 15.1",
						PkgName:         "helm-mirror",
						VulnerabilityID: "SUSE-SU-2019:0048-2",
						Advisory: types.Advisory{
							FixedVersion: "0.2.1-1.7.1",
						},
					},
					Returns: db.PutAdvisoryReturns{},
				},
			},
			putVulnerabilityDetail: []db.PutVulnerabilityDetailExpectation{
				{
					Args: db.PutVulnerabilityDetailArgs{
						TxAnything:      true,
						VulnerabilityID: "SUSE-SU-2019:0048-2",
						Source:          "suse-cvrf",
						Vulnerability: types.VulnerabilityDetail{
							Title: "Security update for helm-mirror",
							References: []string{
								"https://www.suse.com/support/update/announcement/2019/suse-su-20190048-2/",
								"http://lists.suse.com/pipermail/sle-security-updates/2019-July/005660.html",
							},
							Severity: types.SeverityHigh,
						},
					},
					Returns: db.PutVulnerabilityDetailReturns{},
				},
			},
			putSeverity: []db.PutSeverityExpectation{
				{
					Args: db.PutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "SUSE-SU-2019:0048-2",
						Severity:        types.SeverityUnknown,
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tx := &bolt.Tx{}
			mockDBConfig := new(db.MockDBConfig)
			mockDBConfig.ApplyPutAdvisoryExpectations(tc.putAdvisory)
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
		getAdvisories db.GetAdvisoriesExpectation
		expectedError error
		expectedVulns []types.Advisory
	}{
		{
			name:    "happy path",
			version: "8",
			pkgName: "bind",
			getAdvisories: db.GetAdvisoriesExpectation{
				Args: db.GetAdvisoriesArgs{
					Source:  "8",
					PkgName: "bind",
				},
				Returns: db.GetAdvisoriesReturns{
					Advisories: []types.Advisory{
						{
							VulnerabilityID: "openSUSE-SU-2019:0003-1",
							FixedVersion:    "1.3.29-bp150.2.12.1",
						},
					},
				},
			},
			expectedVulns: []types.Advisory{{VulnerabilityID: "openSUSE-SU-2019:0003-1", FixedVersion: "1.3.29-bp150.2.12.1"}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDBConfig := new(db.MockDBConfig)
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
