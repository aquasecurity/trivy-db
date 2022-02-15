package rocky

import (
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
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
					Key: []string{"data-source", "rocky 8"},
					Value: types.DataSource{
						ID:   vulnerability.Rocky,
						Name: "Rocky Linux updateinfo",
						URL:  "https://download.rockylinux.org/pub/rocky/",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-25215", "rocky 8", "bind-export-libs"},
					Value: types.Advisory{
						FixedVersion: "32:9.11.26-4.el8_4",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-25215", "rocky 8", "bind-export-devel"},
					Value: types.Advisory{
						FixedVersion: "32:9.11.26-4.el8_4",
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2021-25215", string(vulnerability.Rocky)},
					Value: types.VulnerabilityDetail{
						Severity: types.SeverityHigh,
						References: []string{
							"https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-25215.json",
						},
						Title:       "Important: bind security update",
						Description: "For more information visit https://errata.rockylinux.org/RLSA-2021:1989",
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2021-25215"},
					Value: map[string]interface{}{},
				},
			},
		},
		{
			name:       "skip advisories for modular package",
			dir:        filepath.Join("testdata", "modular"),
			wantValues: []vulnsrctest.WantValues{},
		},
		{
			name:    "sad path",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "failed to decode Rocky erratum",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs.Update, tt.dir, tt.wantValues, tt.wantErr, nil)
		})
	}
}
