package composer

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
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
					Key: []string{"data-source", "composer::PHP Security Advisories Database"},
					Value: types.DataSource{
						ID:   vulnerability.PhpSecurityAdvisories,
						Name: "PHP Security Advisories Database",
						URL:  "https://github.com/FriendsOfPHP/security-advisories",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2015-5723", "composer::PHP Security Advisories Database", "aws/aws-sdk-php"},
					Value: types.Advisory{
						VulnerableVersions: []string{"\u003e=3.0.0, \u003c3.2.1"},
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2015-5723", "php-security-advisories"},
					Value: types.VulnerabilityDetail{
						ID:    "CVE-2015-5723",
						Title: "Security Misconfiguration Vulnerability in the AWS SDK for PHP",
						References: []string{
							"https://github.com/aws/aws-sdk-php/releases/tag/3.2.1",
						},
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2015-5723"},
					Value: map[string]interface{}{},
				},
			},
		},
		{
			name:    "sad path (dir doesn't exist)",
			dir:     filepath.Join("testdata", "badPath"),
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
			vs := NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
			})
		})
	}
}
