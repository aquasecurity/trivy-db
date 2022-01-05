package govulndb_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-db/pkg/types"
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
					key: []string{"advisory-detail", "CVE-2019-0210", "go::vulndb", "github.com/apache/thrift"},
					value: types.Advisory{
						PatchedVersions:    []string{"0.13.0"},
						VulnerableVersions: []string{">=0.0.0-20151001171628-53dd39833a08, <0.13.0"},
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2019-0210", "go::vulndb"},
					value: types.VulnerabilityDetail{
						Description: "Due to an improper bounds check, parsing maliciously crafted messages can cause panics. If\nthis package is used to parse untrusted input, this may be used as a vector for a denial of\nservice attack.\n",
						References: []string{
							"https://go.googlesource.com/vulndb/+/refs/heads/master/reports/GO-2021-0101.yaml",
							"https://github.com/apache/thrift/commit/264a3f318ed3e9e51573f67f963c8509786bcec2",
							"https://github.com/advisories/GHSA-jq7p-26h5-w78r",
						},
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2020-26160", "go::vulndb", "github.com/dgrijalva/jwt-go/v4"},
					value: types.Advisory{
						PatchedVersions:    []string{"4.0.0-preview1"},
						VulnerableVersions: []string{">=0, <4.0.0-preview1"},
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2020-26160", "go::vulndb"},
					value: types.VulnerabilityDetail{
						Description: "If a JWT contains an audience claim with an array of strings, rather\nthan a single string, and `MapClaims.VerifyAudience` is called with\n`req` set to `false`, then audience verification will be bypassed,\nallowing an invalid set of audiences to be provided.\n",
						References: []string{
							"https://go.googlesource.com/vulndb/+/refs/heads/master/reports/GO-2020-0017.yaml",
							"https://github.com/dgrijalva/jwt-go/commit/ec0a89a131e3e8567adcb21254a5cd20a70ea4ab",
							"https://github.com/dgrijalva/jwt-go/issues/422",
						},
					},
				},
			},
		},
		{
			name:    "broken JSON",
			dir:     "testdata/broken",
			wantErr: "JSON decode error",
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
