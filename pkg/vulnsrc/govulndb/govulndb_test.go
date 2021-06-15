package govulndb_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/govulndb"
)

func TestVulnSrc_Update(t *testing.T) {
	type wantKV struct {
		key   []string
		value interface{}
	}
	tests := []struct {
		name    string
		dir     string
		want    []wantKV
		wantErr string
	}{
		{
			name: "happy path",
			dir:  "testdata/happy",
			want: []wantKV{
				{
					key: []string{"advisory-detail", "CVE-2020-29242", "go::vulndb", "github.com/dhowden/tag"},
					value: types.Advisory{
						PatchedVersions:    []string{"v0.0.0-20201120070457-d52dcb253c63"},
						VulnerableVersions: []string{"< v0.0.0-20201120070457-d52dcb253c63"},
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2020-29242", "go::vulndb"},
					value: types.VulnerabilityDetail{
						ID:          "CVE-2020-29242",
						Description: "Due to improper bounds checking a number of methods can trigger a panic due to attempted\nout-of-bounds reads. If the package is used to parse user supplied input this may be\nused as a vector for a denial of service attack.\n",
						References: []string{
							"https://github.com/dhowden/tag/commit/d52dcb253c63a153632bfee5f269dd411dcd8e96",
							"https://github.com/dhowden/tag/commit/a92213460e4838490ce3066ef11dc823cdc1740e",
							"https://github.com/dhowden/tag/commit/4b595ed4fac79f467594aa92f8953f90f817116e",
							"https://github.com/dhowden/tag/commit/6b18201aa5c5535511802ddfb4e4117686b4866d",
							"https://go.googlesource.com/vulndb/+/refs/heads/main/reports/GO-2021-0097.toml",
						},
						PublishedDate:    utils.MustTimeParse("2021-04-14T12:00:00Z"),
						LastModifiedDate: utils.MustTimeParse("2021-04-14T12:00:00Z"),
					},
				},
			},
		},
		{
			name: "missing module",
			dir:  "testdata/no-module",
			want: []wantKV{
				{
					key: []string{"advisory-detail", "GO-2021-0090", "go::vulndb", "github.com/tendermint/tendermint/types"},
					value: types.Advisory{
						PatchedVersions:    []string{"v0.34.0-dev1.0.20200702134149-480b995a3172"},
						VulnerableVersions: []string{">= v0.33.0, < v0.34.0-dev1.0.20200702134149-480b995a3172"},
					},
				},
				{
					key: []string{"vulnerability-detail", "GO-2021-0090", "go::vulndb"},
					value: types.VulnerabilityDetail{
						ID:          "GO-2021-0090",
						Description: "Proposed commits may contain signatures for blocks not contained within the commit. Instead of skipping\nthese signatures, they cause failure during verification. A malicious proposer can use this to force\nconsensus failures.\n",
						References: []string{
							"https://github.com/tendermint/tendermint/pull/5426",
							"https://go.googlesource.com/vulndb/+/refs/heads/main/reports/GO-2021-0090.toml",
						},
						PublishedDate:    utils.MustTimeParse("2021-04-14T12:00:00Z"),
						LastModifiedDate: utils.MustTimeParse("2021-04-14T12:00:00Z"),
					},
				},
			},
		},
		{
			name:    "broken JSON",
			dir:     "testdata/broken",
			wantErr: "JSON error",
		},
		{
			name:    "sad path",
			dir:     "./sad",
			wantErr: "no such file or directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()

			err := db.Init(tempDir)
			require.NoError(t, err)
			defer db.Close()

			vs := govulndb.NewVulnSrc()
			err = vs.Update(tt.dir)

			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			assert.NoError(t, err)
			require.NoError(t, db.Close()) // Need to close before dbtest.JSONEq is called
			for _, want := range tt.want {
				dbtest.JSONEq(t, db.Path(tempDir), want.key, want.value)
			}
		})
	}
}
