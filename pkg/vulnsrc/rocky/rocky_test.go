package rocky

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-db/pkg/types"
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
					key: []string{"advisory-detail", "CVE-2021-25215", "rocky 8", "bind-export-libs"},
					value: types.Advisory{
						FixedVersion: "32:9.11.26-4.el8_4",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-25215", "rocky 8", "bind-export-devel"},
					value: types.Advisory{
						FixedVersion: "32:9.11.26-4.el8_4",
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2021-25215", vulnerability.Rocky},
					value: types.VulnerabilityDetail{
						Severity: types.SeverityHigh,
						References: []string{
							"https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-25215.json",
						},
						Title:       "Important: bind security update",
						Description: "For more information visit https://errata.rockylinux.org/RLSA-2021:1989",
					},
				},
				{
					key:   []string{"vulnerability-id", "CVE-2021-25215"},
					value: map[string]interface{}{},
				},
			},
		},
		{
			name:       "skip advisories for modular package",
			dir:        filepath.Join("testdata", "modular"),
			wantValues: []want{},
		},
		{
			name:    "sad path",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "failed to decode Rocky erratum",
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
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.NoError(t, db.Close()) // Need to close before dbtest.JSONEq is called
			for _, want := range tt.wantValues {
				dbtest.JSONEq(t, db.Path(tempDir), want.key, want.value)
			}
		})
	}
}
