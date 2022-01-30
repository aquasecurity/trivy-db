package bundler_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bundler"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

func TestVulnSrc_Update(t *testing.T) {
	type want struct {
		key   []string
		value interface{}
	}
	tests := []struct {
		name       string
		dir        string
		wantValues []want
		wantErr    string
	}{
		{
			name: "happy path",
			dir:  filepath.Join("testdata", "happy"),
			wantValues: []want{
				{
					key: []string{"data-source", "rubygems::Ruby Advisory Database"},
					value: types.DataSource{
						ID:   vulnerability.RubySec,
						Name: "Ruby Advisory Database",
						URL:  "https://github.com/rubysec/ruby-advisory-db",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2019-9837", "rubygems::Ruby Advisory Database", "doorkeeper-openid_connect"},
					value: types.Advisory{
						PatchedVersions:    []string{">= 1.5.4"},
						UnaffectedVersions: []string{"< 1.4.0"},
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2019-9837", string(vulnerability.RubySec)},
					value: types.VulnerabilityDetail{
						CvssScoreV3: 6.1,
						References:  []string{"https://github.com/doorkeeper-gem/doorkeeper-openid_connect/blob/master/CHANGELOG.md#v154-2019-02-15"},
						Title:       "Doorkeeper::OpenidConnect Open Redirect",
						Description: "Doorkeeper::OpenidConnect (aka the OpenID Connect extension for Doorkeeper) 1.4.x and 1.5.x before 1.5.4 has an open redirect via the redirect_uri field in an OAuth authorization request (that results in an error response) with the 'openid' scope and a prompt=none value. This allows phishing attacks against the authorization flow.",
					},
				},
				{
					key:   []string{"vulnerability-id", "CVE-2019-9837"},
					value: map[string]interface{}{},
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
			tempDir := t.TempDir()

			err := db.Init(tempDir)
			require.NoError(t, err)
			defer db.Close()

			vs := bundler.NewVulnSrc()
			err = vs.Update(tt.dir)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.NoError(t, db.Close()) // Need to close before dbtest.JSONEq is called
			for _, w := range tt.wantValues {
				dbtest.JSONEq(t, db.Path(tempDir), w.key, w.value, w.key)
			}
		})
	}
}
