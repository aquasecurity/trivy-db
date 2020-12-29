package redhatoval

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"

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
		name             string
		cacheDir         string
		batchUpdate      db.OperationBatchUpdateExpectation
		expectedErrorMsg string
	}{
		{
			name:     "happy path",
			cacheDir: filepath.Join("testdata", "happy"),
			batchUpdate: db.OperationBatchUpdateExpectation{
				Args:    db.OperationBatchUpdateArgs{FnAnything: true},
				Returns: db.OperationBatchUpdateReturns{},
			},
		},
		{
			name:     "broken JSON",
			cacheDir: filepath.Join("testdata", "sad"),
			batchUpdate: db.OperationBatchUpdateExpectation{
				Args:    db.OperationBatchUpdateArgs{FnAnything: true},
				Returns: db.OperationBatchUpdateReturns{},
			},
			expectedErrorMsg: "failed to decode Red Hat OVAL JSON",
		},
		{
			name:     "BatchUpdate returns an error",
			cacheDir: filepath.Join("testdata", "happy"),
			batchUpdate: db.OperationBatchUpdateExpectation{
				Args: db.OperationBatchUpdateArgs{FnAnything: true},
				Returns: db.OperationBatchUpdateReturns{
					Err: errors.New("batch update failed"),
				},
			},
			expectedErrorMsg: "batch update failed",
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
		name              string
		advisories        []RedhatOVAL
		tests             map[string]rpmInfoTest
		putAdvisoryDetail []db.OperationPutAdvisoryDetailExpectation
		expectedErrorMsg  string
	}{
		{
			name: "happy path",
			advisories: []RedhatOVAL{
				{
					ID: "oval:com.redhat.rhsa:def:20152237",
					Metadata: Metadata{
						AffectedList: []Affected{
							{Platforms: []string{"Red Hat Enterprise Linux 7"}},
						},
						References: []Reference{
							{
								Source: "RHSA",
								RefID:  "RHSA-2015:2237",
							},
							{
								Source: "CVE",
								RefID:  "CVE-2015-2675",
							},
						},
						Advisory: Advisory{
							Severity: "",
							Cves: []Cve{
								{CveID: "CVE-2015-2675"},
							},
						},
					},
					Criteria: Criteria{
						Operator: "OR",
						Criterions: []Criterion{
							{Comment: "Red Hat Enterprise Linux must be installed"},
						},
						Criterias: []Criteria{
							{
								Operator: "AND",
								Criterions: []Criterion{
									{Comment: "Red Hat Enterprise Linux 7 is installed"},
								},
								Criterias: []Criteria{
									{
										Operator: "OR",
										Criterias: []Criteria{
											{
												Operator: "AND",
												Criterions: []Criterion{
													{
														Comment: "rest-devel is earlier than 0:0.7.92-3.el7",
														TestRef: "oval:com.redhat.rhsa:tst:20152237001",
													},
													{
														Comment: "rest-devel is signed with Red Hat redhatrelease2 key",
														TestRef: "oval:com.redhat.rhsa:tst:20152237004",
													},
												},
											},
											{
												Operator: "AND",
												Criterions: []Criterion{
													{
														Comment: "rest is earlier than 0:0.7.92-3.el7",
														TestRef: "oval:com.redhat.rhsa:tst:20152237003",
													},
													{
														Comment: "rest is signed with Red Hat redhatrelease2 key",
														TestRef: "oval:com.redhat.rhsa:tst:20152237002",
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:com.redhat.rhsa:tst:20152237001": {
					Name:         "rest-devel",
					FixedVersion: "0:0.7.92-3.el7",
					Arch:         "aarch64|i686|ppc|ppc64|ppc64le|s390|s390x|x86_64",
				},
				"oval:com.redhat.rhsa:tst:20152237003": {
					Name:         "rest",
					FixedVersion: "0:0.7.92-3.el7",
					Arch:         "aarch64|i686|ppc|ppc64|ppc64le|s390|s390x|x86_64",
				},
				"oval:com.redhat.rhsa:tst:20152237004": {
					Name: "rest-devel",
					SignatureKeyID: SignatureKeyID{
						Text:      "199e2f91fd431d51",
						Operation: "equals",
					},
				},
				"oval:com.redhat.rhsa:tst:20152237002": {
					Name: "rest",
					SignatureKeyID: SignatureKeyID{
						Text:      "199e2f91fd431d51",
						Operation: "equals",
					},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "Red Hat Enterprise Linux 7",
						PkgName:         "rest",
						VulnerabilityID: "CVE-2015-2675",
						Advisory:        types.Advisory{FixedVersion: "0:0.7.92-3.el7"},
					},
				},
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "Red Hat Enterprise Linux 7",
						PkgName:         "rest-devel",
						VulnerabilityID: "CVE-2015-2675",
						Advisory:        types.Advisory{FixedVersion: "0:0.7.92-3.el7"},
					},
				},
			},
		},
		{
			name: "invalid platform",
			advisories: []RedhatOVAL{
				{
					ID: "oval:com.redhat.rhsa:def:20152237",
					Metadata: Metadata{
						AffectedList: []Affected{
							{Platforms: []string{"Red Hat Unknown"}},
						},
					},
				},
			},
		},
		{
			name: "invalid major version",
			advisories: []RedhatOVAL{
				{
					ID: "oval:com.redhat.rhsa:def:20152237",
					Metadata: Metadata{
						AffectedList: []Affected{
							{Platforms: []string{"Red Hat Enterprise Linux 100"}},
						},
					},
				},
			},
		},
		{
			name: "PutAdvisory returns an error",
			advisories: []RedhatOVAL{
				{
					Metadata: Metadata{
						AffectedList: []Affected{
							{Platforms: []string{"Red Hat Enterprise Linux 7"}},
						},
						Advisory: Advisory{
							Cves: []Cve{{CveID: "CVE-2015-2675"}},
						},
						References: []Reference{
							{
								Source: "RHSA",
								RefID:  "RHSA-2015:2237",
							},
							{
								Source: "CVE",
								RefID:  "CVE-2015-2675",
							},
						},
					},
					Criteria: Criteria{
						Operator: "AND",
						Criterias: []Criteria{
							{
								Operator: "AND",
								Criterions: []Criterion{
									{Comment: "Red Hat Enterprise Linux 7 is installed"},
								},
								Criterias: []Criteria{
									{
										Operator: "OR",
										Criterias: []Criteria{
											{
												Operator: "AND",
												Criterions: []Criterion{
													{
														Comment: "rest is earlier than 0:0.7.92-3.el7",
														TestRef: "oval:com.redhat.rhsa:tst:20152237003",
													},
													{
														Comment: "rest is signed with Red Hat redhatrelease2 key",
														TestRef: "oval:com.redhat.rhsa:tst:20152237002",
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			tests: map[string]rpmInfoTest{
				"oval:com.redhat.rhsa:tst:20152237001": {
					Name:         "rest-devel",
					FixedVersion: "0:0.7.92-3.el7",
					Arch:         "aarch64|i686|ppc|ppc64|ppc64le|s390|s390x|x86_64",
				},
				"oval:com.redhat.rhsa:tst:20152237003": {
					Name:         "rest",
					FixedVersion: "0:0.7.92-3.el7",
					Arch:         "aarch64|i686|ppc|ppc64|ppc64le|s390|s390x|x86_64",
				},
				"oval:com.redhat.rhsa:tst:20152237004": {
					Name: "rest-devel",
					SignatureKeyID: SignatureKeyID{
						Text:      "199e2f91fd431d51",
						Operation: "equals",
					},
				},
				"oval:com.redhat.rhsa:tst:20152237002": {
					Name: "rest",
					SignatureKeyID: SignatureKeyID{
						Text:      "199e2f91fd431d51",
						Operation: "equals",
					},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "Red Hat Enterprise Linux 7",
						PkgName:         "rest",
						VulnerabilityID: "CVE-2015-2675",
						Advisory:        types.Advisory{FixedVersion: "0:0.7.92-3.el7"},
					},
					Returns: db.OperationPutAdvisoryDetailReturns{
						Err: errors.New("unable to put advisory"),
					},
				},
			},
			expectedErrorMsg: "unable to put advisory",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tx := &bolt.Tx{}
			mockDBConfig := new(db.MockOperation)
			mockDBConfig.ApplyPutAdvisoryDetailExpectations(tc.putAdvisoryDetail)

			ac := VulnSrc{dbc: mockDBConfig}
			err := ac.commit(tx, tc.advisories, tc.tests)

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

func TestVulnSrc_Get(t *testing.T) {
	testCases := []struct {
		name               string
		release            string
		pkgName            string
		getAdvisories      db.OperationGetAdvisoriesExpectation
		expectedErrorMsg   string
		expectedAdvisories []types.Advisory
	}{
		{
			name:    "happy path",
			release: "6",
			pkgName: "package",
			getAdvisories: db.OperationGetAdvisoriesExpectation{
				Args: db.OperationGetAdvisoriesArgs{
					Source:  "Red Hat Enterprise Linux 6",
					PkgName: "package",
				},
				Returns: db.OperationGetAdvisoriesReturns{
					Advisories: []types.Advisory{
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
