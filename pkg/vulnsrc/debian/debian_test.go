package debian_test

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/debian"
)

func TestVulnSrc_Update(t *testing.T) {
	type wantKV struct {
		key   []string
		value interface{}
	}
	tests := []struct {
		name       string
		dir        string
		wantValues []wantKV
		noBuckets  [][]string
		wantErr    string
	}{
		{
			name: "happy path",
			dir:  filepath.Join("testdata", "happy"),
			wantValues: []wantKV{
				// Ref. https://security-tracker.debian.org/tracker/CVE-2021-33560
				{
					key: []string{"advisory-detail", "CVE-2021-33560", "debian oval 9", "libgcrypt20"},
					value: types.Advisory{
						VendorIDs:    []string{"DLA-2691-1"},
						FixedVersion: "1.7.6-2+deb9u4",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-33560", "debian oval 10", "libgcrypt20"},
					value: types.Advisory{
						FixedVersion: "1.8.4-5+deb10u1",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-33560", "debian oval 11", "libgcrypt20"},
					value: types.Advisory{
						FixedVersion: "1.8.7-6",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-29629", "debian 10", "dacs"},
					value: types.Advisory{
						State:    "ignored",
						Severity: types.SeverityLow,
					},
				},
				{
					key: []string{"advisory-detail", "DSA-3714-1", "debian oval 8", "akonadi"},
					value: types.Advisory{
						VendorIDs:    []string{"DSA-3714-1"},
						FixedVersion: "1.13.0-2+deb8u2",
					},
				},
				{
					// wrong no-dsa
					key: []string{"advisory-detail", "CVE-2020-8631", "debian oval 11", "cloud-init"},
					value: types.Advisory{
						FixedVersion: "19.4-2",
					},
				},
			},
			noBuckets: [][]string{
				{"advisory-detail", "CVE-2021-29629", "debian 9"}, // not-affected in debian stretch
				{"advisory-detail", "CVE-2016-4606"},              // not-affected in sid
			},
		},
		{
			name:    "sad broken distributions",
			dir:     filepath.Join("testdata", "broken-distributions"),
			wantErr: "failed to decode Debian distribution JSON",
		},
		{
			name:    "sad broken packages",
			dir:     filepath.Join("testdata", "broken-packages"),
			wantErr: "failed to decode testdata/broken-packages/",
		},
		{
			name:    "sad broken CVE",
			dir:     filepath.Join("testdata", "broken-cve"),
			wantErr: "json decode error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := dbtest.InitTestDB(t, nil)
			dbPath := db.Path(tmpDir)

			vs := debian.NewVulnSrc()

			err := vs.Update(tt.dir)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.NoError(t, db.Close())

			for _, want := range tt.wantValues {
				dbtest.JSONEq(t, dbPath, want.key, want.value, want.key)
			}

			for _, noBucket := range tt.noBuckets {
				dbtest.NoBucket(t, dbPath, noBucket, noBucket)
			}
		})
	}
}

func TestVulnSrc_Get(t *testing.T) {
	type args struct {
		release string
		pkgName string
	}
	tests := []struct {
		name     string
		fixtures []string
		args     args
		want     []types.Advisory
		wantErr  string
	}{
		{
			name:     "happy path",
			fixtures: []string{"testdata/fixtures/debian.yaml"},
			args: args{
				release: "10",
				pkgName: "alpine",
			},
			want: []types.Advisory{
				{
					VulnerabilityID: "CVE-2008-5514",
					FixedVersion:    "2.02-3.1",
				},
				{
					VulnerabilityID: "CVE-2021-38370",
					State:           "no-dsa",
				},
			},
		},
		{
			name:     "broken bucket",
			fixtures: []string{"testdata/fixtures/broken.yaml"},
			args: args{
				release: "10",
				pkgName: "alpine",
			},
			wantErr: "failed to get Debian advisories",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitTestDB(t, tt.fixtures)
			defer db.Close()

			vs := debian.NewVulnSrc()
			got, err := vs.Get(tt.args.release, tt.args.pkgName)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			sort.Slice(got, func(i, j int) bool {
				return got[i].VulnerabilityID < got[j].VulnerabilityID
			})
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
