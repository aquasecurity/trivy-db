package photon

import (
	"errors"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"

	"github.com/aquasecurity/trivy-db/pkg/types"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-db/pkg/db"
)

func TestVulnSrc_Update(t *testing.T) {
	type args struct {
		dir string
	}
	tests := []struct {
		name        string
		args        args
		batchUpdate []db.OperationBatchUpdateExpectation
		wantErr     string
	}{
		{
			name: "happy path",
			args: args{
				dir: "testdata",
			},
			batchUpdate: []db.OperationBatchUpdateExpectation{
				{
					Args: db.OperationBatchUpdateArgs{
						FnAnything: true,
					},
				},
			},
		},
		{
			name: "cache dir doesnt exist",
			args: args{
				dir: "badpathdoesnotexist",
			},
			wantErr: "no such file or directory",
		},
		{
			name: "BatchUpdate returns an error",
			args: args{
				dir: "testdata",
			},
			batchUpdate: []db.OperationBatchUpdateExpectation{
				{
					Args: db.OperationBatchUpdateArgs{
						FnAnything: true,
					},
					Returns: db.OperationBatchUpdateReturns{
						Err: errors.New("error"),
					},
				},
			},
			wantErr: "unable to save Photon advisories",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDBConfig := new(db.MockOperation)
			mockDBConfig.ApplyBatchUpdateExpectations(tt.batchUpdate)

			vs := VulnSrc{
				dbc: mockDBConfig,
			}
			err := vs.Update(tt.args.dir)
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
			} else {
				assert.NoError(t, err, tt.name)
			}
			mockDBConfig.AssertExpectations(t)
		})
	}
}

func TestVulnSrc_commit(t *testing.T) {
	type args struct {
		cves []PhotonCVE
	}
	tests := []struct {
		name                   string
		args                   args
		putAdvisoryDetail      []db.OperationPutAdvisoryDetailExpectation
		putVulnerabilityDetail []db.OperationPutVulnerabilityDetailExpectation
		putSeverity            []db.OperationPutSeverityExpectation
		wantErr                string
	}{
		{
			name: "happy path",
			args: args{
				cves: []PhotonCVE{
					{
						OSVersion: "1.0",
						CveID:     "CVE-2019-10156",
						Pkg:       "ansible",
						CveScore:  5.4,
						AffVer:    "all versions before 2.8.3-1.ph3 are vulnerable",
						ResVer:    "2.8.3-1.ph3",
					},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "Photon OS 1.0",
						PkgName:         "ansible",
						VulnerabilityID: "CVE-2019-10156",
						Advisory: types.Advisory{
							FixedVersion: "2.8.3-1.ph3",
						},
					},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:      true,
						Source:          vulnerability.Photon,
						VulnerabilityID: "CVE-2019-10156",
						Vulnerability: types.VulnerabilityDetail{
							CvssScoreV3: 5.4,
						},
					},
				},
			},
			putSeverity: []db.OperationPutSeverityExpectation{
				{
					Args: db.OperationPutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2019-10156",
						Severity:        types.SeverityUnknown,
					},
				},
			},
		},
		{
			name: "putAdvisoryDetail returns an error",
			args: args{
				cves: []PhotonCVE{
					{
						OSVersion: "1.0",
						CveID:     "CVE-2019-10156",
						Pkg:       "ansible",
						CveScore:  5.4,
						AffVer:    "all versions before 2.8.3-1.ph3 are vulnerable",
						ResVer:    "2.8.3-1.ph3",
					},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "Photon OS 1.0",
						PkgName:         "ansible",
						VulnerabilityID: "CVE-2019-10156",
						Advisory: types.Advisory{
							FixedVersion: "2.8.3-1.ph3",
						},
					},
					Returns: db.OperationPutAdvisoryDetailReturns{
						Err: errors.New("error"),
					},
				},
			},
			wantErr: "failed to save Photon advisory",
		},
		{
			name: "PutVulnerabilityDetail returns an error",
			args: args{
				cves: []PhotonCVE{
					{
						OSVersion: "1.0",
						CveID:     "CVE-2019-10156",
						Pkg:       "ansible",
						CveScore:  5.4,
						AffVer:    "all versions before 2.8.3-1.ph3 are vulnerable",
						ResVer:    "2.8.3-1.ph3",
					},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "Photon OS 1.0",
						PkgName:         "ansible",
						VulnerabilityID: "CVE-2019-10156",
						Advisory: types.Advisory{
							FixedVersion: "2.8.3-1.ph3",
						},
					},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:      true,
						Source:          vulnerability.Photon,
						VulnerabilityID: "CVE-2019-10156",
						Vulnerability: types.VulnerabilityDetail{
							CvssScoreV3: 5.4,
						},
					},
					Returns: db.OperationPutVulnerabilityDetailReturns{
						Err: errors.New("error"),
					},
				},
			},
			wantErr: "failed to save Photon vulnerability detail",
		},
		{
			name: "happy path",
			args: args{
				cves: []PhotonCVE{
					{
						OSVersion: "1.0",
						CveID:     "CVE-2019-10156",
						Pkg:       "ansible",
						CveScore:  5.4,
						AffVer:    "all versions before 2.8.3-1.ph3 are vulnerable",
						ResVer:    "2.8.3-1.ph3",
					},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "Photon OS 1.0",
						PkgName:         "ansible",
						VulnerabilityID: "CVE-2019-10156",
						Advisory: types.Advisory{
							FixedVersion: "2.8.3-1.ph3",
						},
					},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:      true,
						Source:          vulnerability.Photon,
						VulnerabilityID: "CVE-2019-10156",
						Vulnerability: types.VulnerabilityDetail{
							CvssScoreV3: 5.4,
						},
					},
				},
			},
			putSeverity: []db.OperationPutSeverityExpectation{
				{
					Args: db.OperationPutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2019-10156",
						Severity:        types.SeverityUnknown,
					},
					Returns: db.OperationPutSeverityReturns{
						Err: errors.New("error"),
					},
				},
			},
			wantErr: "failed to save Photon vulnerability severity",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDBConfig := new(db.MockOperation)
			mockDBConfig.ApplyPutAdvisoryDetailExpectations(tt.putAdvisoryDetail)
			mockDBConfig.ApplyPutVulnerabilityDetailExpectations(tt.putVulnerabilityDetail)
			mockDBConfig.ApplyPutSeverityExpectations(tt.putSeverity)

			vs := VulnSrc{
				dbc: mockDBConfig,
			}
			err := vs.commit(nil, tt.args.cves)

			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
			} else {
				assert.NoError(t, err, tt.name)
			}
			mockDBConfig.AssertExpectations(t)
		})
	}
}

func TestVulnSrc_Get(t *testing.T) {
	type args struct {
		release string
		pkgName string
	}
	tests := []struct {
		name          string
		args          args
		getAdvisories db.OperationGetAdvisoriesExpectation
		want          []types.Advisory
		wantErr       string
	}{
		{
			name: "happy path",
			args: args{
				release: "1.0",
				pkgName: "ansible",
			},
			getAdvisories: db.OperationGetAdvisoriesExpectation{
				Args: db.OperationGetAdvisoriesArgs{
					Source:  "Photon OS 1.0",
					PkgName: "ansible",
				},
				Returns: db.OperationGetAdvisoriesReturns{
					Advisories: []types.Advisory{
						{
							VulnerabilityID: "CVE-2019-3828",
							FixedVersion:    "2.7.6-2.ph3",
						},
					},
				},
			},
			want: []types.Advisory{
				{
					VulnerabilityID: "CVE-2019-3828",
					FixedVersion:    "2.7.6-2.ph3",
				},
			},
		},
		{
			name: "GetAdvisories returns an error",
			args: args{
				release: "2.0",
				pkgName: "bash",
			},
			getAdvisories: db.OperationGetAdvisoriesExpectation{
				Args: db.OperationGetAdvisoriesArgs{
					Source:  "Photon OS 2.0",
					PkgName: "bash",
				},
				Returns: db.OperationGetAdvisoriesReturns{
					Advisories: nil,
					Err:        errors.New("error"),
				},
			},
			wantErr: "failed to get Photon advisories",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDBConfig := new(db.MockOperation)
			mockDBConfig.ApplyGetAdvisoriesExpectation(tt.getAdvisories)

			vs := VulnSrc{dbc: mockDBConfig}
			got, err := vs.Get(tt.args.release, tt.args.pkgName)
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
			} else {
				assert.NoError(t, err, tt.name)
			}
			assert.Equal(t, tt.want, got, tt.name)
		})
	}
}
