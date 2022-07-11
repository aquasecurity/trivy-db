package govulndb_test

import (
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/govulndb"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

func TestVulnSrc_Update(t *testing.T) {
	tests := []struct {
		name    string
		dir     string
		want    []vulnsrctest.WantValues
		wantErr string
	}{
		{
			name: "happy path",
			dir:  "testdata/happy",
			want: []vulnsrctest.WantValues{
				{
					Key: []string{"data-source", "go::The Go Vulnerability Database"},
					Value: types.DataSource{
						ID:   vulnerability.GoVulnDB,
						Name: "The Go Vulnerability Database",
						URL:  "https://github.com/golang/vulndb",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2019-0210", "go::The Go Vulnerability Database", "github.com/apache/thrift"},
					Value: types.Advisory{
						PatchedVersions:    []string{"0.13.0"},
						VulnerableVersions: []string{">=0.0.0-20151001171628-53dd39833a08, <0.13.0"},
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2019-0210", string(vulnerability.GoVulnDB)},
					Value: types.VulnerabilityDetail{
						Description: "Due to an improper bounds check, parsing maliciously crafted messages can cause panics. If\nthis package is used to parse untrusted input, this may be used as a vector for a denial of\nservice attack.\n",
						References: []string{
							"https://go.googlesource.com/vulndb/+/refs/heads/master/reports/GO-2021-0101.yaml",
							"https://github.com/apache/thrift/commit/264a3f318ed3e9e51573f67f963c8509786bcec2",
							"https://github.com/advisories/GHSA-jq7p-26h5-w78r",
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2020-26160", "go::The Go Vulnerability Database", "github.com/dgrijalva/jwt-go/v4"},
					Value: types.Advisory{
						PatchedVersions:    []string{"4.0.0-preview1"},
						VulnerableVersions: []string{">=0.0.0-0, <4.0.0-preview1"},
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2020-26160", string(vulnerability.GoVulnDB)},
					Value: types.VulnerabilityDetail{
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
			vs := govulndb.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.want,
				WantErr:    tt.wantErr,
			})
		})
	}
}
