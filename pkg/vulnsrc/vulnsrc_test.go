package vulnsrc

// TODO: move this test under trivy-db

//
//import (
//	"errors"
//	"testing"
//	"time"
//
//	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
//
//	"github.com/stretchr/testify/require"
//
//	"github.com/stretchr/testify/assert"
//	"k8s.io/utils/clock"
//	ct "k8s.io/utils/clock/testing"
//
//	"github.com/aquasecurity/trivy-db/pkg/db"
//	"github.com/aquasecurity/trivy-db/pkg/types"
//)
//
//func TestNewUpdater(t *testing.T) {
//	type args struct {
//		cacheDir string
//		light    bool
//		interval time.Duration
//	}
//	type want struct {
//		cacheDir  string
//		dbType    db.Type
//		interval  time.Duration
//		clock     clock.Clock
//		optimizer Optimizer
//	}
//	tests := []struct {
//		name string
//		args args
//		want want
//	}{
//		{
//			name: "full",
//			args: args{
//				cacheDir: "/full",
//				light:    false,
//				interval: 60 * time.Hour,
//			},
//			want: want{
//				cacheDir:  "/full",
//				dbType:    db.TypeFull,
//				clock:     clock.RealClock{},
//				interval:  60 * time.Hour,
//				optimizer: fullOptimizer{},
//			},
//		},
//		{
//			name: "light",
//			args: args{
//				cacheDir: "/light",
//				light:    true,
//				interval: 60 * time.Minute,
//			},
//			want: want{
//				cacheDir:  "/light",
//				dbType:    db.TypeLight,
//				clock:     clock.RealClock{},
//				interval:  60 * time.Minute,
//				optimizer: lightOptimizer{},
//			},
//		},
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			got := NewUpdater(tt.args.cacheDir, tt.args.light, tt.args.interval)
//
//			assert.NotNil(t, got.dbc, tt.name)
//			assert.Equal(t, All, got.updateMap, tt.name)
//			assert.Equal(t, tt.want.cacheDir, got.cacheDir, tt.name)
//			assert.Equal(t, tt.want.dbType, got.dbType, tt.name)
//			assert.Equal(t, tt.want.interval, got.updateInterval, tt.name)
//			assert.IsType(t, tt.want.clock, got.clock, tt.name)
//			assert.IsType(t, tt.want.optimizer, got.optimizer, tt.name)
//		})
//	}
//}
//
//func TestUpdater_Update(t *testing.T) {
//	fixedNextUpdateTime := time.Date(2019, 1, 1, 12, 0, 0, 0, time.UTC)
//	fixedUpdatedAtTime := time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)
//
//	type fields struct {
//		UpdateMap      map[string]VulnSrc
//		CacheDir       string
//		DBType         db.Type
//		UpdateInterval time.Duration
//		Clock          clock.Clock
//	}
//	type args struct {
//		targets []string
//	}
//	tests := []struct {
//		name          string
//		fields        fields
//		args          args
//		update        []types.UpdateExpectation
//		setMetadata   []SetMetadataExpectation
//		storeMetadata []StoreMetadataExpectation
//		optimize      []OptimizeExpectation
//		wantErr       string
//	}{
//		{
//			name: "happy test",
//			fields: fields{
//				CacheDir:       "cache",
//				DBType:         db.TypeFull,
//				UpdateInterval: 12 * time.Hour,
//				Clock:          ct.NewFakeClock(time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)),
//			},
//			args: args{
//				targets: []string{"test"},
//			},
//			update: []types.UpdateExpectation{
//				{
//					Args: types.UpdateArgs{
//						Dir: "cache",
//					},
//					Returns: types.UpdateReturns{},
//				},
//			},
//			setMetadata: []SetMetadataExpectation{
//				{
//					Args: SetMetadataArgs{
//						Metadata: db.Metadata{
//							Version:    1,
//							Type:       db.TypeFull,
//							NextUpdate: fixedNextUpdateTime,
//							UpdatedAt:  fixedUpdatedAtTime,
//						},
//					},
//					Returns: SetMetadataReturns{},
//				},
//			},
//			storeMetadata: []StoreMetadataExpectation{
//				{
//					Args: StoreMetadataArgs{
//						Metadata: db.Metadata{
//							Version:    1,
//							Type:       db.TypeFull,
//							NextUpdate: fixedNextUpdateTime,
//							UpdatedAt:  fixedUpdatedAtTime,
//						},
//						DirAnything: true,
//					},
//					Returns: StoreMetadataReturns{},
//				},
//			},
//			optimize: []OptimizeExpectation{
//				{Returns: OptimizeReturns{}},
//			},
//		},
//		{
//			name: "unknown target",
//			fields: fields{
//				CacheDir:       "cache",
//				DBType:         db.TypeFull,
//				UpdateInterval: 12 * time.Hour,
//				Clock:          ct.NewFakeClock(time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)),
//			},
//			args: args{
//				targets: []string{"unknown"},
//			},
//			wantErr: "unknown does not supported yet",
//		},
//		{
//			name: "Update returns an error",
//			fields: fields{
//				CacheDir:       "cache",
//				DBType:         db.TypeFull,
//				UpdateInterval: 12 * time.Hour,
//				Clock:          ct.NewFakeClock(time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)),
//			},
//			args: args{
//				targets: []string{"test"},
//			},
//			update: []types.UpdateExpectation{
//				{
//					Args: types.UpdateArgs{
//						Dir: "cache",
//					},
//					Returns: types.UpdateReturns{
//						Err: errors.New("error"),
//					},
//				},
//			},
//			wantErr: "error in test update",
//		},
//		{
//			name: "SetMetadata returns an error",
//			fields: fields{
//				CacheDir:       "cache",
//				DBType:         db.TypeFull,
//				UpdateInterval: 12 * time.Hour,
//				Clock:          ct.NewFakeClock(time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)),
//			},
//			args: args{
//				targets: []string{"test"},
//			},
//			update: []types.UpdateExpectation{
//				{
//					Args: types.UpdateArgs{
//						Dir: "cache",
//					},
//					Returns: types.UpdateReturns{},
//				},
//			},
//			setMetadata: []SetMetadataExpectation{
//				{
//					Args: SetMetadataArgs{
//						Metadata: db.Metadata{
//							Version:    1,
//							Type:       db.TypeFull,
//							NextUpdate: fixedNextUpdateTime,
//							UpdatedAt:  fixedUpdatedAtTime,
//						},
//					},
//					Returns: SetMetadataReturns{
//						Err: errors.New("error"),
//					},
//				},
//			},
//			wantErr: "failed to save metadata",
//		},
//		{
//			name: "StoreMetadata returns an error",
//			fields: fields{
//				CacheDir:       "cache",
//				DBType:         db.TypeFull,
//				UpdateInterval: 12 * time.Hour,
//				Clock:          ct.NewFakeClock(time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)),
//			},
//			args: args{
//				targets: []string{"test"},
//			},
//			update: []types.UpdateExpectation{
//				{
//					Args: types.UpdateArgs{
//						Dir: "cache",
//					},
//					Returns: types.UpdateReturns{},
//				},
//			},
//			setMetadata: []SetMetadataExpectation{
//				{
//					Args: SetMetadataArgs{
//						Metadata: db.Metadata{
//							Version:    1,
//							Type:       db.TypeFull,
//							NextUpdate: fixedNextUpdateTime,
//							UpdatedAt:  fixedUpdatedAtTime,
//						},
//					},
//				},
//			},
//			storeMetadata: []StoreMetadataExpectation{
//				{
//					Args: StoreMetadataArgs{
//						Metadata: db.Metadata{
//							Version:    1,
//							Type:       db.TypeFull,
//							NextUpdate: fixedNextUpdateTime,
//							UpdatedAt:  fixedUpdatedAtTime,
//						},
//						DirAnything: true,
//					},
//					Returns: StoreMetadataReturns{
//						Err: errors.New("error"),
//					},
//				},
//			},
//			wantErr: "failed to store metadata",
//		},
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			mockVulnSrc := new(types.MockVulnSrc)
//			mockVulnSrc.ApplyUpdateExpectations(tt.update)
//
//			mockDBOperation := new(MockOperation)
//			mockDBOperation.ApplySetMetadataExpectations(tt.setMetadata)
//			mockDBOperation.ApplyStoreMetadataExpectations(tt.storeMetadata)
//
//			mockOptimizer := new(MockOptimizer)
//			mockOptimizer.ApplyOptimizeExpectations(tt.optimize)
//
//			u := Updater{
//				dbc: mockDBOperation,
//				updateMap: map[string]VulnSrc{
//					"test": mockVulnSrc,
//				},
//				cacheDir:       tt.fields.CacheDir,
//				dbType:         tt.fields.DBType,
//				updateInterval: tt.fields.UpdateInterval,
//				clock:          tt.fields.Clock,
//				optimizer:      mockOptimizer,
//			}
//			err := u.Update(tt.args.targets)
//			switch {
//			case tt.wantErr != "":
//				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
//			default:
//				assert.NoError(t, err, tt.name)
//			}
//
//			mockVulnSrc.AssertExpectations(t)
//			mockDBOperation.AssertExpectations(t)
//			mockOptimizer.AssertExpectations(t)
//		})
//	}
//}
//
//func Test_fullOptimizer_Optimize(t *testing.T) {
//	tests := []struct {
//		name                            string
//		forEachSeverity                 db.OperationForEachSeverityExpectation
//		deleteSeverityBucket            db.OperationDeleteSeverityBucketExpectation
//		deleteVulnerabilityDetailBucket db.OperationDeleteVulnerabilityDetailBucketExpectation
//		deleteAdvisoryDetailBucket      db.OperationDeleteAdvisoryDetailBucketExpectation
//		wantErr                         string
//	}{
//		{
//			name: "happy path",
//			forEachSeverity: db.OperationForEachSeverityExpectation{
//				Args:    db.OperationForEachSeverityArgs{FnAnything: true},
//				Returns: db.OperationForEachSeverityReturns{},
//			},
//		},
//		{
//			name: "OperationForEachSeverity returns an error",
//			forEachSeverity: db.OperationForEachSeverityExpectation{
//				Args: db.OperationForEachSeverityArgs{FnAnything: true},
//				Returns: db.OperationForEachSeverityReturns{
//					Err: errors.New("error"),
//				},
//			},
//			wantErr: "failed to iterate severity",
//		},
//		{
//			name: "DeleteSeverityBucket returns an error",
//			forEachSeverity: db.OperationForEachSeverityExpectation{
//				Args:    db.OperationForEachSeverityArgs{FnAnything: true},
//				Returns: db.OperationForEachSeverityReturns{},
//			},
//			deleteSeverityBucket: db.OperationDeleteSeverityBucketExpectation{
//				Returns: db.OperationDeleteSeverityBucketReturns{
//					Err: errors.New("error"),
//				},
//			},
//			wantErr: "failed to delete severity bucket",
//		},
//		{
//			name: "DeleteVulnerabilityDetailBucket returns an error",
//			forEachSeverity: db.OperationForEachSeverityExpectation{
//				Args:    db.OperationForEachSeverityArgs{FnAnything: true},
//				Returns: db.OperationForEachSeverityReturns{},
//			},
//			deleteVulnerabilityDetailBucket: db.OperationDeleteVulnerabilityDetailBucketExpectation{
//				Returns: db.OperationDeleteVulnerabilityDetailBucketReturns{
//					Err: errors.New("error"),
//				},
//			},
//			wantErr: "failed to delete vulnerability detail bucket",
//		},
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			mockDBOperation := new(db.MockOperation)
//			mockDBOperation.ApplyForEachSeverityExpectation(tt.forEachSeverity)
//			mockDBOperation.ApplyDeleteSeverityBucketExpectation(tt.deleteSeverityBucket)
//			mockDBOperation.ApplyDeleteVulnerabilityDetailBucketExpectation(tt.deleteVulnerabilityDetailBucket)
//			mockDBOperation.ApplyDeleteAdvisoryDetailBucketExpectation(tt.deleteAdvisoryDetailBucket)
//			o := fullOptimizer{
//				dbc: mockDBOperation,
//			}
//			err := o.Optimize()
//			switch {
//			case tt.wantErr != "":
//				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
//			default:
//				assert.NoError(t, err, tt.name)
//			}
//		})
//	}
//}
//
//func Test_lightOptimizer_Optimize(t *testing.T) {
//	tests := []struct {
//		name                            string
//		forEachSeverity                 db.OperationForEachSeverityExpectation
//		deleteVulnerabilityDetailBucket db.OperationDeleteVulnerabilityDetailBucketExpectation
//		wantErr                         string
//	}{
//		{
//			name: "happy path",
//			forEachSeverity: db.OperationForEachSeverityExpectation{
//				Args:    db.OperationForEachSeverityArgs{FnAnything: true},
//				Returns: db.OperationForEachSeverityReturns{},
//			},
//			deleteVulnerabilityDetailBucket: db.OperationDeleteVulnerabilityDetailBucketExpectation{
//				Returns: db.OperationDeleteVulnerabilityDetailBucketReturns{},
//			},
//		},
//		{
//			name: "OperationForEachSeverity returns an error",
//			forEachSeverity: db.OperationForEachSeverityExpectation{
//				Args: db.OperationForEachSeverityArgs{
//					FnAnything: true,
//				},
//				Returns: db.OperationForEachSeverityReturns{
//					Err: errors.New("error"),
//				},
//			},
//			wantErr: "failed to iterate severity",
//		},
//		{
//			name: "DeleteVulnerabilityDetailBucket returns an error",
//			forEachSeverity: db.OperationForEachSeverityExpectation{
//				Args: db.OperationForEachSeverityArgs{
//					FnAnything: true,
//				},
//				Returns: db.OperationForEachSeverityReturns{},
//			},
//			deleteVulnerabilityDetailBucket: db.OperationDeleteVulnerabilityDetailBucketExpectation{
//				Returns: db.OperationDeleteVulnerabilityDetailBucketReturns{
//					Err: errors.New("error"),
//				},
//			},
//			wantErr: "failed to delete vulnerability detail bucket",
//		},
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			mockDBConfig := new(db.MockOperation)
//			mockDBConfig.ApplyForEachSeverityExpectation(tt.forEachSeverity)
//			mockDBConfig.ApplyDeleteVulnerabilityDetailBucketExpectation(tt.deleteVulnerabilityDetailBucket)
//
//			o := lightOptimizer{
//				dbOp: mockDBConfig,
//			}
//			err := o.Optimize()
//			switch {
//			case tt.wantErr != "":
//				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
//			default:
//				assert.NoError(t, err, tt.name)
//			}
//		})
//	}
//}
//
//func Test_fullOptimize(t *testing.T) {
//	tests := []struct {
//		name                              string
//		putVulnerabilityExpectation       db.OperationPutVulnerabilityExpectation
//		putAdvisoryExpectations           []db.OperationPutAdvisoryExpectation
//		getVulnerabilityDetailExpectation db.OperationGetVulnerabilityDetailExpectation
//		getAdvisoryDetailExpectation      db.OperationGetAdvisoryDetailsExpectation
//		wantErr                           string
//	}{
//		{
//			name: "happy path",
//			putAdvisoryExpectations: []db.OperationPutAdvisoryExpectation{
//				{
//					Args: db.OperationPutAdvisoryArgs{
//						TxAnything:      true,
//						Source:          "redhat",
//						PkgName:         "pkg1",
//						VulnerabilityID: "CVE-2020-1234",
//						Advisory: types.Advisory{
//							VulnerabilityID: "CVE-2020-1234",
//							FixedVersion:    "v1.2.3",
//						},
//					},
//					Returns: db.OperationPutAdvisoryReturns{},
//				},
//				{
//					Args: db.OperationPutAdvisoryArgs{
//						TxAnything:      true,
//						Source:          "ubuntu",
//						PkgName:         "pkg2",
//						VulnerabilityID: "CVE-2020-1234",
//						Advisory: types.Advisory{
//							VulnerabilityID: "CVE-2020-1234",
//							FixedVersion:    "v2.3.4",
//						},
//					},
//					Returns: db.OperationPutAdvisoryReturns{},
//				},
//			},
//			putVulnerabilityExpectation: db.OperationPutVulnerabilityExpectation{
//				Args: db.OperationPutVulnerabilityArgs{
//					TxAnything:      true,
//					VulnerabilityID: "CVE-2020-1234",
//					Vulnerability: types.Vulnerability{
//						Title:       "test title",
//						Description: "test description",
//						Severity:    types.SeverityMedium.String(),
//						VendorSeverity: types.VendorSeverity{
//							"redhat": types.SeverityCritical,
//							"ubuntu": types.SeverityLow,
//						},
//						CVSS: map[string]types.CVSS{
//							"redhat": {
//								V2Vector: "AV:N/AC:M/Au:N/C:N/I:P/A:N",
//								V2Score:  4.5,
//								V3Vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
//								V3Score:  5.6,
//							},
//						},
//						CweIDs:     []string{"CWE-134"},
//						References: []string{"http://example.com"},
//					},
//				},
//				Returns: db.OperationPutVulnerabilityReturns{},
//			},
//			getVulnerabilityDetailExpectation: db.OperationGetVulnerabilityDetailExpectation{
//				Args: db.OperationGetVulnerabilityDetailArgs{
//					CveID: "CVE-2020-1234",
//				},
//				Returns: db.OperationGetVulnerabilityDetailReturns{
//					Detail: map[string]types.VulnerabilityDetail{
//						"redhat": {
//							CvssScore:    4.5,
//							CvssVector:   "AV:N/AC:M/Au:N/C:N/I:P/A:N",
//							CvssScoreV3:  5.6,
//							CvssVectorV3: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
//							Severity:     types.SeverityCritical,
//							SeverityV3:   types.SeverityCritical,
//							CweIDs:       []string{"CWE-134"},
//							References:   []string{"http://example.com"},
//							Title:        "test title",
//							Description:  "test description",
//						},
//						"ubuntu": {
//							Severity: types.SeverityLow,
//						},
//					},
//				},
//			},
//			getAdvisoryDetailExpectation: db.OperationGetAdvisoryDetailsExpectation{
//				Args: db.OperationGetAdvisoryDetailsArgs{
//					CveID: "CVE-2020-1234",
//				},
//				Returns: db.OperationGetAdvisoryDetailsReturns{
//					Details: []types.AdvisoryDetail{
//						{
//							PlatformName: "redhat",
//							PackageName:  "pkg1",
//							AdvisoryItem: types.Advisory{
//								VulnerabilityID: "CVE-2020-1234",
//								FixedVersion:    "v1.2.3",
//							},
//						},
//						{
//							PlatformName: "ubuntu",
//							PackageName:  "pkg2",
//							AdvisoryItem: types.Advisory{
//								VulnerabilityID: "CVE-2020-1234",
//								FixedVersion:    "v2.3.4",
//							},
//						},
//					},
//				},
//			},
//		},
//		{
//			name:                        "happy path when vulnerability is rejected",
//			putAdvisoryExpectations:     []db.OperationPutAdvisoryExpectation{},
//			putVulnerabilityExpectation: db.OperationPutVulnerabilityExpectation{},
//			getVulnerabilityDetailExpectation: db.OperationGetVulnerabilityDetailExpectation{
//				Args: db.OperationGetVulnerabilityDetailArgs{
//					CveID: "CVE-2020-1234",
//				},
//				Returns: db.OperationGetVulnerabilityDetailReturns{
//					Detail: map[string]types.VulnerabilityDetail{
//						"redhat": {
//							CvssScore:    4.5,
//							CvssVector:   "AV:N/AC:M/Au:N/C:N/I:P/A:N",
//							CvssScoreV3:  5.6,
//							CvssVectorV3: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
//							Severity:     types.SeverityCritical,
//							SeverityV3:   types.SeverityCritical,
//							CweIDs:       []string{"CWE-134"},
//							References:   []string{"http://example.com"},
//							Title:        "test title",
//							Description:  "** REJECT ** test description",
//						},
//						"ubuntu": {
//							Severity: types.SeverityLow,
//						},
//					},
//				},
//			},
//		},
//		{
//			name: "happy path when both vulnerability and advisories are present",
//			putAdvisoryExpectations: []db.OperationPutAdvisoryExpectation{
//				{
//					Args: db.OperationPutAdvisoryArgs{
//						TxAnything:      true,
//						Source:          "redhat",
//						PkgName:         "test",
//						VulnerabilityID: "CVE-2020-1234",
//						Advisory: types.Advisory{
//							FixedVersion: "",
//						},
//					},
//				},
//			},
//			putVulnerabilityExpectation: db.OperationPutVulnerabilityExpectation{
//				Args: db.OperationPutVulnerabilityArgs{
//					TxAnything:      true,
//					VulnerabilityID: "CVE-2020-1234",
//					Vulnerability: types.Vulnerability{
//						Title:       "test title",
//						Description: "test description",
//						Severity:    types.SeverityCritical.String(),
//						VendorSeverity: types.VendorSeverity{
//							"redhat": types.SeverityCritical,
//							"ubuntu": types.SeverityLow,
//						},
//						CVSS:       map[string]types.CVSS{},
//						CweIDs:     []string{"CWE-134"},
//						References: []string{"test reference"},
//					},
//				},
//				Returns: db.OperationPutVulnerabilityReturns{},
//			},
//			getVulnerabilityDetailExpectation: db.OperationGetVulnerabilityDetailExpectation{
//				Args: db.OperationGetVulnerabilityDetailArgs{
//					CveID: "CVE-2020-1234",
//				},
//				Returns: db.OperationGetVulnerabilityDetailReturns{
//					Detail: map[string]types.VulnerabilityDetail{
//						"redhat": {
//							ID:          "CVE-2020-1234",
//							Severity:    types.SeverityCritical,
//							SeverityV3:  0,
//							CweIDs:      []string{"CWE-134"},
//							References:  []string{"test reference"},
//							Title:       "test title",
//							Description: "test description",
//						},
//						"ubuntu": {
//							Severity: types.SeverityLow,
//						},
//					},
//				},
//			},
//			getAdvisoryDetailExpectation: db.OperationGetAdvisoryDetailsExpectation{
//				Args: db.OperationGetAdvisoryDetailsArgs{
//					CveID: "CVE-2020-1234",
//				},
//				Returns: db.OperationGetAdvisoryDetailsReturns{
//					Details: []types.AdvisoryDetail{
//						{
//							PlatformName: "redhat",
//							PackageName:  "test",
//							AdvisoryItem: types.Advisory{
//								FixedVersion: "",
//							},
//						},
//					},
//				},
//			},
//		},
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			mockDBOperation := new(db.MockOperation)
//			mockDBOperation.ApplyPutAdvisoryExpectations(tt.putAdvisoryExpectations)
//			mockDBOperation.ApplyPutVulnerabilityExpectation(tt.putVulnerabilityExpectation)
//			mockDBOperation.ApplyGetVulnerabilityDetailExpectation(tt.getVulnerabilityDetailExpectation)
//			mockDBOperation.ApplyGetAdvisoryDetailsExpectation(tt.getAdvisoryDetailExpectation)
//			o := fullOptimizer{
//				dbc:        mockDBOperation,
//				vulnClient: vulnerability.New(mockDBOperation),
//			}
//			err := o.fullOptimize(nil, "CVE-2020-1234")
//			switch {
//			case tt.wantErr != "":
//				require.NotNil(t, err)
//				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
//			default:
//				require.NoError(t, err)
//			}
//		})
//	}
//}
//
//func Test_lightOptimize(t *testing.T) {
//	tests := []struct {
//		name                              string
//		putAdvisoryExpectations           []db.OperationPutAdvisoryExpectation
//		putVulnerabilityExpectation       db.OperationPutVulnerabilityExpectation
//		putSeverityExpectation            db.OperationPutSeverityExpectation
//		getVulnerabilityDetailExpectation db.OperationGetVulnerabilityDetailExpectation
//		getAdvisoryDetailExpectation      db.OperationGetAdvisoryDetailsExpectation
//		wantErr                           string
//	}{
//		{
//			name: "happy path",
//			putAdvisoryExpectations: []db.OperationPutAdvisoryExpectation{
//				{
//					Args: db.OperationPutAdvisoryArgs{
//						TxAnything:      true,
//						Source:          "redhat",
//						PkgName:         "pkg1",
//						VulnerabilityID: "CVE-2020-1234",
//						Advisory: types.Advisory{
//							VulnerabilityID: "CVE-2020-1234",
//							FixedVersion:    "v1.2.3",
//						},
//					},
//					Returns: db.OperationPutAdvisoryReturns{},
//				},
//			},
//			putVulnerabilityExpectation: db.OperationPutVulnerabilityExpectation{
//				Args: db.OperationPutVulnerabilityArgs{
//					TxAnything:      true,
//					VulnerabilityID: "CVE-2020-1234",
//					Vulnerability: types.Vulnerability{
//						VendorSeverity: types.VendorSeverity{
//							"redhat": types.SeverityHigh,
//							"ubuntu": types.SeverityLow,
//						},
//					},
//				},
//				Returns: db.OperationPutVulnerabilityReturns{},
//			},
//			putSeverityExpectation: db.OperationPutSeverityExpectation{
//				Args: db.OperationPutSeverityArgs{
//					TxAnything:      true,
//					VulnerabilityID: "CVE-2020-1234",
//					Severity:        types.SeverityHigh,
//				},
//				Returns: db.OperationPutSeverityReturns{},
//			},
//			getVulnerabilityDetailExpectation: db.OperationGetVulnerabilityDetailExpectation{
//				Args: db.OperationGetVulnerabilityDetailArgs{
//					CveID: "CVE-2020-1234",
//				},
//				Returns: db.OperationGetVulnerabilityDetailReturns{
//					Detail: map[string]types.VulnerabilityDetail{
//						"redhat": {
//							ID:          "CVE-2020-1234",
//							Severity:    types.SeverityHigh,
//							SeverityV3:  0,
//							CweIDs:      []string{"CWE-134"},
//							References:  []string{"test reference"},
//							Title:       "test title",
//							Description: "test description",
//						},
//						"ubuntu": {
//							Severity: types.SeverityLow,
//						},
//					},
//				},
//			},
//			getAdvisoryDetailExpectation: db.OperationGetAdvisoryDetailsExpectation{
//				Args: db.OperationGetAdvisoryDetailsArgs{
//					CveID: "CVE-2020-1234",
//				},
//				Returns: db.OperationGetAdvisoryDetailsReturns{
//					Details: []types.AdvisoryDetail{
//						{
//							PlatformName: "redhat",
//							PackageName:  "pkg1",
//							AdvisoryItem: types.Advisory{
//								VulnerabilityID: "CVE-2020-1234",
//								FixedVersion:    "v1.2.3",
//							},
//						},
//					},
//				},
//			},
//		},
//		{
//			name:                        "happy path when vulnerability is rejected",
//			putVulnerabilityExpectation: db.OperationPutVulnerabilityExpectation{},
//			putSeverityExpectation:      db.OperationPutSeverityExpectation{},
//			getVulnerabilityDetailExpectation: db.OperationGetVulnerabilityDetailExpectation{
//				Args: db.OperationGetVulnerabilityDetailArgs{
//					CveID: "CVE-2020-1234",
//				},
//				Returns: db.OperationGetVulnerabilityDetailReturns{
//					Detail: map[string]types.VulnerabilityDetail{
//						"redhat": {
//							ID:          "CVE-2020-1234",
//							Severity:    types.SeverityHigh,
//							SeverityV3:  0,
//							CweIDs:      []string{"CWE-134"},
//							References:  []string{"test reference"},
//							Title:       "test title",
//							Description: "** REJECT ** test description",
//						},
//						"ubuntu": {
//							Severity: types.SeverityLow,
//						},
//					},
//				},
//			},
//		},
//		{
//			name: "happy path with advisories",
//			putAdvisoryExpectations: []db.OperationPutAdvisoryExpectation{
//				{
//					Args: db.OperationPutAdvisoryArgs{
//						TxAnything:      true,
//						Source:          "redhat",
//						PkgName:         "test",
//						VulnerabilityID: "CVE-2020-1234",
//						Advisory: types.Advisory{
//							FixedVersion: "1",
//						},
//					},
//				},
//				{
//					Args: db.OperationPutAdvisoryArgs{
//						TxAnything:      true,
//						Source:          "redhat",
//						PkgName:         "test2",
//						VulnerabilityID: "CVE-2020-1234",
//						Advisory: types.Advisory{
//							FixedVersion: "2",
//						},
//					},
//				},
//			},
//			putVulnerabilityExpectation: db.OperationPutVulnerabilityExpectation{
//				Args: db.OperationPutVulnerabilityArgs{
//					TxAnything:      true,
//					VulnerabilityID: "CVE-2020-1234",
//					Vulnerability: types.Vulnerability{
//						VendorSeverity: types.VendorSeverity{
//							"redhat": types.SeverityHigh,
//						},
//					},
//				},
//				Returns: db.OperationPutVulnerabilityReturns{},
//			},
//			putSeverityExpectation: db.OperationPutSeverityExpectation{
//				Args: db.OperationPutSeverityArgs{
//					TxAnything:      true,
//					VulnerabilityID: "CVE-2020-1234",
//					Severity:        types.SeverityHigh,
//				},
//				Returns: db.OperationPutSeverityReturns{},
//			},
//			getVulnerabilityDetailExpectation: db.OperationGetVulnerabilityDetailExpectation{
//				Args: db.OperationGetVulnerabilityDetailArgs{
//					CveID: "CVE-2020-1234",
//				},
//				Returns: db.OperationGetVulnerabilityDetailReturns{
//					Detail: map[string]types.VulnerabilityDetail{
//						"redhat": {
//							ID:          "CVE-2020-123",
//							Severity:    types.SeverityHigh,
//							SeverityV3:  0,
//							CweIDs:      []string{"CWE-134"},
//							References:  []string{"test reference"},
//							Title:       "test title",
//							Description: "test description",
//						},
//					},
//				},
//			},
//			getAdvisoryDetailExpectation: db.OperationGetAdvisoryDetailsExpectation{
//				Args: db.OperationGetAdvisoryDetailsArgs{
//					CveID: "CVE-2020-1234",
//				},
//				Returns: db.OperationGetAdvisoryDetailsReturns{
//					Details: []types.AdvisoryDetail{
//						{
//							PlatformName: "redhat",
//							PackageName:  "test",
//							AdvisoryItem: types.Advisory{
//								FixedVersion: "1",
//							},
//						},
//						{
//							PlatformName: "redhat",
//							PackageName:  "test2",
//							AdvisoryItem: types.Advisory{
//								FixedVersion: "2",
//							},
//						},
//					},
//				},
//			},
//		},
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			mockDBOperation := new(db.MockOperation)
//			mockDBOperation.ApplyPutAdvisoryExpectations(tt.putAdvisoryExpectations)
//			mockDBOperation.ApplyPutVulnerabilityExpectation(tt.putVulnerabilityExpectation)
//			mockDBOperation.ApplyPutSeverityExpectation(tt.putSeverityExpectation)
//			mockDBOperation.ApplyGetVulnerabilityDetailExpectation(tt.getVulnerabilityDetailExpectation)
//			mockDBOperation.ApplyGetAdvisoryDetailsExpectation(tt.getAdvisoryDetailExpectation)
//			o := lightOptimizer{
//				dbOp:       mockDBOperation,
//				vulnClient: vulnerability.New(mockDBOperation),
//			}
//			err := o.lightOptimize("CVE-2020-1234", nil)
//			switch {
//			case tt.wantErr != "":
//				require.NotNil(t, err)
//				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
//			default:
//				require.NoError(t, err)
//			}
//		})
//	}
//}
