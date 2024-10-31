package bundler_test

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bundler"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
)

func TestVulnSrc_Update(t *testing.T) {
	tests := []struct {
		name       string
		dir        string
		wantValues []vulnsrctest.WantValues
		wantErr    string
	}{
		{
			name: "happy path",
			dir:  filepath.Join("testdata", "happy"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"data-source", "rubygems::Ruby Advisory Database"},
					Value: types.DataSource{
						ID:   vulnerability.RubySec,
						Name: "Ruby Advisory Database",
						URL:  "https://github.com/rubysec/ruby-advisory-db",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2019-9837", "rubygems::Ruby Advisory Database", "doorkeeper-openid_connect"},
					Value: types.Advisory{
						PatchedVersions:    []string{">= 1.5.4"},
						UnaffectedVersions: []string{"< 1.4.0"},
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2019-9837", string(vulnerability.RubySec)},
					Value: types.VulnerabilityDetail{
						CvssScoreV3: 6.1,
						References:  []string{"https://github.com/doorkeeper-gem/doorkeeper-openid_connect/blob/master/CHANGELOG.md#v154-2019-02-15"},
						Title:       "Doorkeeper::OpenidConnect Open Redirect",
						Description: "Doorkeeper::OpenidConnect (aka the OpenID Connect extension for Doorkeeper) 1.4.x and 1.5.x before 1.5.4 has an open redirect via the redirect_uri field in an OAuth authorization request (that results in an error response) with the 'openid' scope and a prompt=none value. This allows phishing attacks against the authorization flow.",
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2019-9837"},
					Value: map[string]interface{}{},
				},
			},
		},
		{
			name:    "sad path",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "failed to unmarshal YAML",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := bundler.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
			})
		})
	}
}
