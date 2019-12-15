package susecvrf

import (
	"errors"
	"fmt"
	"os"
	"testing"

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

// func TestVulnSrc_Commit(t *testing.T) {
// 	type putAdvisoryInput struct {
// 		source   string
// 		pkgName  string
// 		cveID    string
// 		advisory types.Advisory
// 	}
// 	type putAdvisory struct {
// 		input  putAdvisoryInput
// 		output error
// 	}
//
// 	type putVulnerabilityDetailInput struct {
// 		cveID  string
// 		source string
// 		vuln   types.VulnerabilityDetail
// 	}
// 	type putVulnerabilityDetail struct {
// 		input  putVulnerabilityDetailInput
// 		output error
// 	}
//
// 	type putSeverityInput struct {
// 		cveID    string
// 		severity types.Severity
// 	}
// 	type putSeverity struct {
// 		input  putSeverityInput
// 		output error
// 	}
// 	testCases := []struct {
// 		name                       string
// 		cves                       []SuseOVAL
// 		putAdvisoryList            []putAdvisory
// 		putVulnerabilityDetailList []putVulnerabilityDetail
// 		putSeverityList            []putSeverity
// 		expectedErrorMsg           string
// 	}{}
//
// 	for _, tc := range testCases {
// 		t.Run(tc.name, func(t *testing.T) {
// 			tx := &bolt.Tx{}
// 			mockDBConfig := new(db.MockDBConfig)
//
// 			for _, pa := range tc.putAdvisoryList {
// 				mockDBConfig.On("PutAdvisory", tx, pa.input.source, pa.input.pkgName,
// 					pa.input.cveID, pa.input.advisory).Return(pa.output)
// 			}
// 			for _, pvd := range tc.putVulnerabilityDetailList {
// 				mockDBConfig.On("PutVulnerabilityDetail", tx, pvd.input.cveID,
// 					pvd.input.source, pvd.input.vuln).Return(pvd.output)
// 			}
// 			for _, ps := range tc.putSeverityList {
// 				mockDBConfig.On("PutSeverity", tx, ps.input.cveID,
// 					ps.input.severity).Return(ps.output)
// 			}
//
// 			ac := VulnSrc{dbc: mockDBConfig}
// 			err := ac.commit(tx, tc.cves)
//
// 			switch {
// 			case tc.expectedErrorMsg != "":
// 				assert.Contains(t, err.Error(), tc.expectedErrorMsg, tc.name)
// 			default:
// 				assert.NoError(t, err, tc.name)
// 			}
// 			mockDBConfig.AssertExpectations(t)
// 		})
// 	}
// }
//
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
		version       string
		pkgName       string
		getAdvisories getAdvisories
		expectedError error
		expectedVulns []types.Advisory
	}{
		{
			name:    "happy path",
			version: "8",
			pkgName: "bind",
			getAdvisories: getAdvisories{
				input: getAdvisoriesInput{
					version: "8",
					pkgName: "bind",
				},
				output: getAdvisoriesOutput{
					advisories: []types.Advisory{
						{VulnerabilityID: "openSUSE-SU-2019:0003-1", FixedVersion: "1.3.29-bp150.2.12.1"},
					},
					err: nil,
				},
			},
			expectedError: nil,
			expectedVulns: []types.Advisory{{VulnerabilityID: "openSUSE-SU-2019:0003-1", FixedVersion: "1.3.29-bp150.2.12.1"}},
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
			expectedPlatformName: "OpenSUSE Leap 42.3",
		},
		{
			inputPlatformName:    "openSUSE Leap 42.3 NonFree",
			expectedPlatformName: "OpenSUSE Leap 42.3",
		},
		{
			inputPlatformName:    "openSUSE Leap 15.1",
			expectedPlatformName: "OpenSUSE Leap 15.1",
		},
		{
			inputPlatformName:    "openSUSE Leap 15.1 NonFree",
			expectedPlatformName: "OpenSUSE Leap 15.1",
		},
		// Below tests exclude platformNames
		{
			// invalid versions
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
		actual := getOSVersion(tc.inputPlatformName)
		assert.Equal(t, tc.expectedPlatformName, actual, fmt.Sprintf("input data: %s", tc.inputPlatformName))
	}
}
