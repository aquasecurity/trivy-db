package db_test

import (
	"testing"

	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/types"
	redhatovaltypes "github.com/aquasecurity/trivy-db/pkg/vulnsrc/redhat-oval/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
)

func TestConfig_SaveAdvisoryDetails(t *testing.T) {
	type want struct {
		key   []string
		value types.Advisory
	}
	tests := []struct {
		name     string
		fixtures []string
		vulnID   string
		want     []want
		wantErr  string
	}{
		{
			name:     "happy path",
			fixtures: []string{"testdata/fixtures/advisory-detail.yaml"},
			vulnID:   "CVE-2019-14904",
			want: []want{
				{
					key: []string{"alpine 3.14", "ansible", "CVE-2019-14904"},
					value: types.Advisory{
						FixedVersion: "2.9.3-r0",
					},
				},
				{
					key: []string{"debian 10", "ansible", "CVE-2019-14904"},
					value: types.Advisory{
						FixedVersion: "2.3.4",
					},
				},
				{
					key: []string{"Red Hat", "cpe:/o:redhat:enterprise_linux:6::server", "ansible", "CVE-2019-14904"},
					value: types.Advisory{
						FixedVersion: "3.4.5",
					},
				},
			},
		},
		{
			name:     "missing ID",
			fixtures: []string{"testdata/fixtures/advisory-detail.yaml"},
			vulnID:   "CVE-2019-9999",
			want:     nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize DB for testing
			tmpDir := dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			dbc := db.Config{}
			err := dbc.BatchUpdate(func(tx *bolt.Tx) error {
				return dbc.SaveAdvisoryDetails(tx, tt.vulnID)
			})

			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.NoError(t, db.Close()) // Need to close before dbtest.JSONEq is called
			for _, w := range tt.want {
				dbtest.JSONEq(t, db.Path(tmpDir), w.key, w.value)
			}
		})
	}
}

func TestConfig_SaveRhsaAdvisoryDetails(t *testing.T) {
	type want struct {
		key   []string
		value redhatovaltypes.Advisory
	}
	tests := []struct {
		name         string
		fixtures     []string
		vulnID       string
		rejectedCves []string
		want         []want
		wantErr      string
	}{
		{
			name:     "happy path without reject cves",
			fixtures: []string{"testdata/fixtures/rhsa-advisory-detail.yaml"},
			vulnID:   "RHSA-2021:4151",
			want: []want{
				{
					key: []string{"Red Hat", "python2", "RHSA-2021:4151"},
					value: redhatovaltypes.Advisory{
						Entries: []redhatovaltypes.Entry{
							{
								Cves: []redhatovaltypes.CveEntry{
									{
										ID:       "CVE-2020-28493",
										Severity: 1,
									},
									{
										ID:       "CVE-2021-20095",
										Severity: 2,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:         "happy path with reject cves",
			fixtures:     []string{"testdata/fixtures/rhsa-advisory-detail.yaml"},
			vulnID:       "RHSA-2021:4151",
			rejectedCves: []string{"CVE-2021-20095"},
			want: []want{
				{
					key: []string{"Red Hat", "python2", "RHSA-2021:4151"},
					value: redhatovaltypes.Advisory{
						Entries: []redhatovaltypes.Entry{
							{
								Cves: []redhatovaltypes.CveEntry{
									{
										ID:       "CVE-2020-28493",
										Severity: 1,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize DB for testing
			tmpDir := dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			dbc := db.Config{}
			err := dbc.BatchUpdate(func(tx *bolt.Tx) error {
				return dbc.SaveRhsaAdvisoryDetails(tx, tt.vulnID, tt.rejectedCves)
			})

			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.NoError(t, db.Close()) // Need to close before dbtest.JSONEq is called
			for _, w := range tt.want {
				dbtest.JSONEq(t, db.Path(tmpDir), w.key, w.value)
			}
		})
	}
}
