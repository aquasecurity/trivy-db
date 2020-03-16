package vulnsrc

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
	"k8s.io/utils/clock"
	ct "k8s.io/utils/clock/testing"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
)

func TestNewUpdater(t *testing.T) {
	type args struct {
		cacheDir string
		light    bool
		interval time.Duration
	}
	type want struct {
		cacheDir  string
		dbType    db.Type
		interval  time.Duration
		clock     clock.Clock
		optimizer Optimizer
	}
	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "full",
			args: args{
				cacheDir: "/full",
				light:    false,
				interval: 60 * time.Hour,
			},
			want: want{
				cacheDir:  "/full",
				dbType:    db.TypeFull,
				clock:     clock.RealClock{},
				interval:  60 * time.Hour,
				optimizer: fullOptimizer{},
			},
		},
		{
			name: "light",
			args: args{
				cacheDir: "/light",
				light:    true,
				interval: 60 * time.Minute,
			},
			want: want{
				cacheDir:  "/light",
				dbType:    db.TypeLight,
				clock:     clock.RealClock{},
				interval:  60 * time.Minute,
				optimizer: lightOptimizer{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewUpdater(tt.args.cacheDir, tt.args.light, tt.args.interval)

			assert.NotNil(t, got.dbc, tt.name)
			assert.Equal(t, updateMap, got.updateMap, tt.name)
			assert.Equal(t, tt.want.cacheDir, got.cacheDir, tt.name)
			assert.Equal(t, tt.want.dbType, got.dbType, tt.name)
			assert.Equal(t, tt.want.interval, got.updateInterval, tt.name)
			assert.IsType(t, tt.want.clock, got.clock, tt.name)
			assert.IsType(t, tt.want.optimizer, got.optimizer, tt.name)
		})
	}
}

func TestUpdater_Update(t *testing.T) {
	fixedNextUpdateTime := time.Date(2019, 1, 1, 12, 0, 0, 0, time.UTC)
	fixedUpdatedAtTime := time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)

	type fields struct {
		UpdateMap      map[string]VulnSrc
		CacheDir       string
		DBType         db.Type
		UpdateInterval time.Duration
		Clock          clock.Clock
	}
	type args struct {
		targets []string
	}
	tests := []struct {
		name        string
		fields      fields
		args        args
		update      []types.UpdateExpectation
		setMetadata []SetMetadataExpectation
		optimize    []OptimizeExpectation
		wantErr     string
	}{
		{
			name: "happy test",
			fields: fields{
				CacheDir:       "cache",
				DBType:         db.TypeFull,
				UpdateInterval: 12 * time.Hour,
				Clock:          ct.NewFakeClock(time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)),
			},
			args: args{
				targets: []string{"test"},
			},
			update: []types.UpdateExpectation{
				{
					Args: types.UpdateArgs{
						Dir: "cache",
					},
					Returns: types.UpdateReturns{},
				},
			},
			setMetadata: []SetMetadataExpectation{
				{
					Args: SetMetadataArgs{
						Metadata: db.Metadata{
							Version:    1,
							Type:       db.TypeFull,
							NextUpdate: fixedNextUpdateTime,
							UpdatedAt:  fixedUpdatedAtTime,
						},
					},
					Returns: SetMetadataReturns{},
				},
			},
			optimize: []OptimizeExpectation{
				{Returns: OptimizeReturns{}},
			},
		},
		{
			name: "unknown target",
			fields: fields{
				CacheDir:       "cache",
				DBType:         db.TypeFull,
				UpdateInterval: 12 * time.Hour,
				Clock:          ct.NewFakeClock(time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)),
			},
			args: args{
				targets: []string{"unknown"},
			},
			wantErr: "unknown does not supported yet",
		},
		{
			name: "Update returns an error",
			fields: fields{
				CacheDir:       "cache",
				DBType:         db.TypeFull,
				UpdateInterval: 12 * time.Hour,
				Clock:          ct.NewFakeClock(time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)),
			},
			args: args{
				targets: []string{"test"},
			},
			update: []types.UpdateExpectation{
				{
					Args: types.UpdateArgs{
						Dir: "cache",
					},
					Returns: types.UpdateReturns{
						Err: errors.New("error"),
					},
				},
			},
			wantErr: "error in test update",
		},
		{
			name: "SetMetadata returns an error",
			fields: fields{
				CacheDir:       "cache",
				DBType:         db.TypeFull,
				UpdateInterval: 12 * time.Hour,
				Clock:          ct.NewFakeClock(time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)),
			},
			args: args{
				targets: []string{"test"},
			},
			update: []types.UpdateExpectation{
				{
					Args: types.UpdateArgs{
						Dir: "cache",
					},
					Returns: types.UpdateReturns{},
				},
			},
			setMetadata: []SetMetadataExpectation{
				{
					Args: SetMetadataArgs{
						Metadata: db.Metadata{
							Version:    1,
							Type:       db.TypeFull,
							NextUpdate: fixedNextUpdateTime,
							UpdatedAt:  fixedUpdatedAtTime,
						},
					},
					Returns: SetMetadataReturns{
						Err: errors.New("error"),
					},
				},
			},
			wantErr: "failed to save metadata",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockVulnSrc := new(types.MockVulnSrc)
			mockVulnSrc.ApplyUpdateExpectations(tt.update)

			mockDBOperation := new(MockOperation)
			mockDBOperation.ApplySetMetadataExpectations(tt.setMetadata)

			mockOptimizer := new(MockOptimizer)
			mockOptimizer.ApplyOptimizeExpectations(tt.optimize)

			u := Updater{
				dbc: mockDBOperation,
				updateMap: map[string]VulnSrc{
					"test": mockVulnSrc,
				},
				cacheDir:       tt.fields.CacheDir,
				dbType:         tt.fields.DBType,
				updateInterval: tt.fields.UpdateInterval,
				clock:          tt.fields.Clock,
				optimizer:      mockOptimizer,
			}
			err := u.Update(tt.args.targets)
			switch {
			case tt.wantErr != "":
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
			default:
				assert.NoError(t, err, tt.name)
			}

			mockVulnSrc.AssertExpectations(t)
			mockDBOperation.AssertExpectations(t)
			mockOptimizer.AssertExpectations(t)
		})
	}
}

func Test_fullOptimizer_Optimize(t *testing.T) {
	tests := []struct {
		name                            string
		forEachSeverity                 db.ForEachSeverityExpectation
		deleteSeverityBucket            db.DeleteSeverityBucketExpectation
		deleteVulnerabilityDetailBucket db.DeleteVulnerabilityDetailBucketExpectation
		wantErr                         string
	}{
		{
			name: "happy path",
			forEachSeverity: db.ForEachSeverityExpectation{
				Args:    db.ForEachSeverityArgs{FnAnything: true},
				Returns: db.ForEachSeverityReturns{},
			},
		},
		{
			name: "ForEachSeverity returns an error",
			forEachSeverity: db.ForEachSeverityExpectation{
				Args: db.ForEachSeverityArgs{FnAnything: true},
				Returns: db.ForEachSeverityReturns{
					Err: errors.New("error"),
				},
			},
			wantErr: "failed to iterate severity",
		},
		{
			name: "DeleteSeverityBucket returns an error",
			forEachSeverity: db.ForEachSeverityExpectation{
				Args:    db.ForEachSeverityArgs{FnAnything: true},
				Returns: db.ForEachSeverityReturns{},
			},
			deleteSeverityBucket: db.DeleteSeverityBucketExpectation{
				Returns: db.DeleteSeverityBucketReturns{
					Err: errors.New("error"),
				},
			},
			wantErr: "failed to delete severity bucket",
		},
		{
			name: "DeleteVulnerabilityDetailBucket returns an error",
			forEachSeverity: db.ForEachSeverityExpectation{
				Args:    db.ForEachSeverityArgs{FnAnything: true},
				Returns: db.ForEachSeverityReturns{},
			},
			deleteVulnerabilityDetailBucket: db.DeleteVulnerabilityDetailBucketExpectation{
				Returns: db.DeleteVulnerabilityDetailBucketReturns{
					Err: errors.New("error"),
				},
			},
			wantErr: "failed to delete vulnerability detail bucket",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDBOperation := new(db.MockOperation)
			mockDBOperation.ApplyForEachSeverityExpectation(tt.forEachSeverity)
			mockDBOperation.ApplyDeleteSeverityBucketExpectation(tt.deleteSeverityBucket)
			mockDBOperation.ApplyDeleteVulnerabilityDetailBucketExpectation(tt.deleteVulnerabilityDetailBucket)

			o := fullOptimizer{
				dbOp: mockDBOperation,
			}
			err := o.Optimize()
			switch {
			case tt.wantErr != "":
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
			default:
				assert.NoError(t, err, tt.name)
			}
		})
	}
}

func Test_lightOptimizer_Optimize(t *testing.T) {
	tests := []struct {
		name                            string
		forEachSeverity                 db.ForEachSeverityExpectation
		deleteVulnerabilityDetailBucket db.DeleteVulnerabilityDetailBucketExpectation
		wantErr                         string
	}{
		{
			name: "happy path",
			forEachSeverity: db.ForEachSeverityExpectation{
				Args:    db.ForEachSeverityArgs{FnAnything: true},
				Returns: db.ForEachSeverityReturns{},
			},
			deleteVulnerabilityDetailBucket: db.DeleteVulnerabilityDetailBucketExpectation{
				Returns: db.DeleteVulnerabilityDetailBucketReturns{},
			},
		},
		{
			name: "ForEachSeverity returns an error",
			forEachSeverity: db.ForEachSeverityExpectation{
				Args: db.ForEachSeverityArgs{
					FnAnything: true,
				},
				Returns: db.ForEachSeverityReturns{
					Err: errors.New("error"),
				},
			},
			wantErr: "failed to iterate severity",
		},
		{
			name: "DeleteVulnerabilityDetailBucket returns an error",
			forEachSeverity: db.ForEachSeverityExpectation{
				Args: db.ForEachSeverityArgs{
					FnAnything: true,
				},
				Returns: db.ForEachSeverityReturns{},
			},
			deleteVulnerabilityDetailBucket: db.DeleteVulnerabilityDetailBucketExpectation{
				Returns: db.DeleteVulnerabilityDetailBucketReturns{
					Err: errors.New("error"),
				},
			},
			wantErr: "failed to delete vulnerability detail bucket",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDBConfig := new(db.MockOperation)
			mockDBConfig.ApplyForEachSeverityExpectation(tt.forEachSeverity)
			mockDBConfig.ApplyDeleteVulnerabilityDetailBucketExpectation(tt.deleteVulnerabilityDetailBucket)

			o := lightOptimizer{
				dbc: mockDBConfig,
			}
			err := o.Optimize()
			switch {
			case tt.wantErr != "":
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
			default:
				assert.NoError(t, err, tt.name)
			}
		})
	}
}

type mockVulnOperation struct {
	getVulnerabilityDetail func(cveID string) (map[string]types.VulnerabilityDetail, error)
}

func (m mockVulnOperation) GetVulnerabilityDetail(cveID string) (map[string]types.VulnerabilityDetail, error) {
	if m.getVulnerabilityDetail != nil {
		return m.getVulnerabilityDetail(cveID)
	}
	return map[string]types.VulnerabilityDetail{}, nil
}

func Test_fullOptimize(t *testing.T) {
	oldgetDetailFunc := getDetailFunc
	defer func() {
		getDetailFunc = oldgetDetailFunc
	}()

	getDetailFunc = func(vulnID string) (severity types.Severity, vendorSeverity types.VendorSeverity, s string, s2 string, strings []string) {
		return types.SeverityCritical, types.VendorSeverity{
			"redhat": types.SeverityHigh,
			"ubuntu": types.SeverityLow,
		}, "test title", "test description", []string{"test reference"}
	}

	mockDBOperation := new(db.MockOperation)
	o := fullOptimizer{
		dbConfig: mockVulnOperation{
			getVulnerabilityDetail: func(cveID string) (m map[string]types.VulnerabilityDetail, err error) {
				return map[string]types.VulnerabilityDetail{
					"redhat": {
						ID:          "CVE-2020-1234",
						CvssScore:   4.3,
						CvssScoreV3: 5.6,
						Severity:    types.SeverityHigh,
						SeverityV3:  types.SeverityCritical,
						Title:       "test vulnerability",
						Description: "a test vulnerability where vendor rates it lower than NVD",
					},
					"ubuntu": {
						ID:          "CVE-2020-1234",
						CvssScore:   1.2,
						CvssScoreV3: 3.4,
						Severity:    types.SeverityLow,
						SeverityV3:  types.SeverityMedium,
						Title:       "test vulnerability",
						Description: "a test vulnerability where vendor rates it lower than NVD",
					},
				}, nil
			},
		},
		dbOp: mockDBOperation,
	}
	mockDBOperation.ApplyPutVulnerabilityExpectation(db.PutVulnerabilityExpectation{
		Args: db.PutVulnerabilityArgs{
			TxAnything:      true,
			VulnerabilityID: "CVE-2020-123",
			Vulnerability: types.Vulnerability{
				Title:       "test title",
				Description: "test description",
				Severity:    types.SeverityCritical.String(),
				VendorSeverity: types.VendorSeverity{
					"redhat": types.SeverityHigh,
					"ubuntu": types.SeverityLow,
				},
				References: []string{"test reference"},
			},
		},
		Returns: db.PutVulnerabilityReturns{},
	})

	err := o.fullOptimize("CVE-2020-123", nil)
	require.NoError(t, err)
}
