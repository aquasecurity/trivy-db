package composer

import (
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"path/filepath"
	"testing"
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
					key: []string{"data-source", "composer::PHP Security Advisories Database"},
					value: types.DataSource{
						ID:   vulnerability.PhpSecurityAdvisories,
						Name: "PHP Security Advisories Database",
						URL:  "https://github.com/FriendsOfPHP/security-advisories",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2015-5723", "composer::PHP Security Advisories Database", "aws/aws-sdk-php"},
					value: types.Advisory{
						VulnerableVersions: []string{"\u003e=3.0.0, \u003c3.2.1"},
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2015-5723", "php-security-advisories"},
					value: types.VulnerabilityDetail{
						ID:    "CVE-2015-5723",
						Title: "Security Misconfiguration Vulnerability in the AWS SDK for PHP",
						References: []string{
							"https://github.com/aws/aws-sdk-php/releases/tag/3.2.1",
						},
					},
				},
				{
					key:   []string{"vulnerability-id", "CVE-2015-5723"},
					value: map[string]interface{}{},
				},
			},
		},
		{
			name:    "sad path (dir doesn't exist)",
			dir:     filepath.Join("testdata", "badpathdoesnotexist"),
			wantErr: "no such file or directory",
		},
		{
			name:    "sad path (failed to decode)",
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

			vs := NewVulnSrc()
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
