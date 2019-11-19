package vulnsrc

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/stretchr/testify/mock"

	"k8s.io/utils/clock"
	ct "k8s.io/utils/clock/testing"

	"github.com/aquasecurity/trivy-db/pkg/db"
)

type MockOptimizer struct {
	mock.Mock
}

func (_m *MockOptimizer) Optimize() error {
	ret := _m.Called()
	return ret.Error(0)
}

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
	type setMetadata struct {
		input  db.Metadata
		output error
	}
	type update struct {
		input  string
		output error
	}
	type optimize struct {
		output error
	}
	type mocks struct {
		update      []update
		setMetadata []setMetadata
		optimize    []optimize
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		mocks   mocks
		wantErr string
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
			mocks: mocks{
				update: []update{{input: "cache"}},
				setMetadata: []setMetadata{
					{
						input: db.Metadata{
							Version:    1,
							Type:       db.TypeFull,
							NextUpdate: time.Date(2019, 1, 1, 12, 0, 0, 0, time.UTC),
							UpdatedAt:  time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC),
						},
					},
				},
				optimize: []optimize{{output: nil}},
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
			mocks: mocks{
				update: []update{{input: "cache", output: errors.New("error")}},
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
			mocks: mocks{
				update: []update{{input: "cache"}},
				setMetadata: []setMetadata{
					{
						input: db.Metadata{
							Version:    1,
							Type:       db.TypeFull,
							NextUpdate: time.Date(2019, 1, 1, 12, 0, 0, 0, time.UTC),
							UpdatedAt:  time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC),
						},
						output: errors.New("error"),
					},
				},
			},
			wantErr: "failed to save metadata",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockVulnSrc := new(types.MockVulnSrc)
			for _, u := range tt.mocks.update {
				mockVulnSrc.On("Update", u.input).Return(u.output)
			}

			mockDBConfig := new(db.MockDBConfig)
			for _, sm := range tt.mocks.setMetadata {
				mockDBConfig.On("SetMetadata", sm.input).Return(sm.output)
			}

			mockOptimizer := new(MockOptimizer)
			for _, o := range tt.mocks.optimize {
				mockOptimizer.On("Optimize").Return(o.output)
			}

			u := Updater{
				dbc: mockDBConfig,
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
			mockDBConfig.AssertExpectations(t)
			mockOptimizer.AssertExpectations(t)
		})
	}
}
