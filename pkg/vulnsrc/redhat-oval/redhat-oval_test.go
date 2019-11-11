package redhatoval

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
	bolt "github.com/etcd-io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
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
	}{
		{
			name:     "happy path",
			cacheDir: filepath.Join("testdata", "happy"),
		},
		{
			name:             "broken JSON",
			cacheDir:         filepath.Join("testdata", "sad"),
			expectedErrorMsg: "failed to decode Red Hat OVAL JSON",
		},
		{
			name:             "BatchUpdate returns an error",
			cacheDir:         filepath.Join("testdata", "happy"),
			batchUpdateErr:   errors.New("batch update failed"),
			expectedErrorMsg: "batch update failed",
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

	testCases := []struct {
		name             string
		advisories       []RedhatOVAL
		putAdvisoryList  []putAdvisory
		expectedErrorMsg string
	}{
		{
			name: "happy path",
			advisories: []RedhatOVAL{
				{
					ID: "oval:com.redhat.rhsa:def:20152237",
					Affecteds: []Affected{
						{Platforms: []string{"Red Hat Enterprise Linux 8"}},
					},
					Advisory: Advisory{
						Severity: "",
						Cves: []Cve{
							{CveID: "CVE-2015-2675"},
							{CveID: "CVE-2015-2676"},
						},
					},
					Criteria: Criteria{
						Operator: "AND",
						Criterias: []Criteria{
							{
								Operator: "OR",
								Criterions: []Criterion{
									{Comment: "Red Hat Enterprise Linux 7 Client is installed"},
									{Comment: "Red Hat Enterprise Linux 7 Server is installed"},
									{Comment: "Red Hat Enterprise Linux 7 Workstation is installed"},
									{Comment: "Red Hat Enterprise Linux 7 ComputeNode is installed"},
								},
							},
							{
								Operator: "OR",
								Criterias: []Criteria{
									{
										Operator: "AND",
										Criterions: []Criterion{
											{Comment: "rest-devel is earlier than 0:0.7.92-3.el7"},
											{Comment: "rest-devel is signed with Red Hat redhatrelease2 key"},
										},
									},
									{
										Operator: "AND",
										Criterions: []Criterion{
											{Comment: "rest is earlier than 0:0.7.92-3.el7"},
											{Comment: "rest is signed with Red Hat redhatrelease2 key"},
										},
									},
								},
							},
						},
					},
				},
			},
			putAdvisoryList: []putAdvisory{
				{
					input: putAdvisoryInput{
						source:   "Red Hat Enterprise Linux 8",
						pkgName:  "rest",
						cveID:    "CVE-2015-2675",
						advisory: types.Advisory{FixedVersion: "0:0.7.92-3.el7"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "Red Hat Enterprise Linux 8",
						pkgName:  "rest",
						cveID:    "CVE-2015-2676",
						advisory: types.Advisory{FixedVersion: "0:0.7.92-3.el7"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "Red Hat Enterprise Linux 8",
						pkgName:  "rest-devel",
						cveID:    "CVE-2015-2675",
						advisory: types.Advisory{FixedVersion: "0:0.7.92-3.el7"},
					},
				},
				{
					input: putAdvisoryInput{
						source:   "Red Hat Enterprise Linux 8",
						pkgName:  "rest-devel",
						cveID:    "CVE-2015-2676",
						advisory: types.Advisory{FixedVersion: "0:0.7.92-3.el7"},
					},
				},
			},
		},
		{
			name: "invalid platform",
			advisories: []RedhatOVAL{
				{
					ID: "oval:com.redhat.rhsa:def:20152237",
					Affecteds: []Affected{
						{Platforms: []string{"Red Hat Unknown"}},
					},
				},
			},
		},
		{
			name: "invalid major version",
			advisories: []RedhatOVAL{
				{
					ID: "oval:com.redhat.rhsa:def:20152237",
					Affecteds: []Affected{
						{Platforms: []string{"Red Hat Enterprise Linux 100"}},
					},
				},
			},
		},
		{
			name: "PutAdvisory returns an error",
			advisories: []RedhatOVAL{
				{
					Affecteds: []Affected{
						{Platforms: []string{"Red Hat Enterprise Linux 8"}},
					},
					Advisory: Advisory{
						Cves: []Cve{{CveID: "CVE-2015-2675"}},
					},
					Criteria: Criteria{
						Operator: "AND",
						Criterias: []Criteria{
							{
								Operator: "OR",
								Criterias: []Criteria{
									{
										Operator: "AND",
										Criterions: []Criterion{
											{Comment: "rest is earlier than 0:0.7.92-3.el7"},
											{Comment: "rest is signed with Red Hat redhatrelease2 key"},
										},
									},
								},
							},
						},
					},
				},
			},
			putAdvisoryList: []putAdvisory{
				{
					input: putAdvisoryInput{
						source:   "Red Hat Enterprise Linux 8",
						pkgName:  "rest",
						cveID:    "CVE-2015-2675",
						advisory: types.Advisory{FixedVersion: "0:0.7.92-3.el7"},
					},
					output: errors.New("unable to put advisory"),
				},
			},
			expectedErrorMsg: "unable to put advisory",
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

			ac := VulnSrc{dbc: mockDBConfig}
			err := ac.commit(tx, tc.advisories)

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
		release            string
		pkgName            string
		getAdvisories      getAdvisories
		expectedErrorMsg   string
		expectedAdvisories []types.Advisory
	}{
		{
			name:    "happy path",
			release: "6",
			pkgName: "package",
			getAdvisories: getAdvisories{
				input: getAdvisoriesInput{
					bucket:  "Red Hat Enterprise Linux 6",
					pkgName: "package",
				},
				output: getAdvisoriesOutput{
					advisories: []types.Advisory{
						{
							VulnerabilityID: "CVE-2019-0123",
							FixedVersion:    "1.2.3",
						},
					},
				},
			},
			expectedAdvisories: []types.Advisory{
				{
					VulnerabilityID: "CVE-2019-0123",
					FixedVersion:    "1.2.3",
				},
			},
		},
		{
			name:    "GetAdvisories returns an error",
			release: "6",
			pkgName: "package",
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
			advisories, err := vs.Get(tc.release, tc.pkgName)

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
