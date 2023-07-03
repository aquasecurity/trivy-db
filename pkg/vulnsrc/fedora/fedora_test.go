package fedora

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			name: "everything package",
			dir:  filepath.Join("testdata", "everything"),
			wantValues: []want{
				{
					key: []string{"advisory-detail", "CVE-2021-41159", "fedora 35", "freerdp-libs-debuginfo"},
					value: types.Advisory{
						FixedVersion: "2:2.4.1-1.fc35",
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2021-41159", string(vulnerability.Fedora)},
					value: types.VulnerabilityDetail{
						Severity: types.SeverityHigh,
						References: []string{
							"https://bugzilla.redhat.com/show_bug.cgi?id=2015189",
						},
						Title:       "freerdp-2.4.1-1.fc35 guacamole-server-1.3.0-9.fc35 remmina-1.4.21-1.fc35",
						Description: "- Update to 2.4.1 containing security fixes for CVE-2021-41159 and CVE-2021-41160.\n- Remmina 1.4.21 with bugfixes.\n\n",
					},
				},
				{
					key:   []string{"vulnerability-id", "CVE-2021-41159"},
					value: map[string]interface{}{},
				},
			},
		},
		{
			name: "modular package",
			dir:  filepath.Join("testdata", "module"),
			wantValues: []want{
				{
					key: []string{"advisory-detail", "CVE-2021-35623", "fedora 35", "mysql:8.0::community-mysql"},
					value: types.Advisory{
						FixedVersion: "8.0.27-1.module_f35+13269+c9322734",
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2021-35623", string(vulnerability.Fedora)},
					value: types.VulnerabilityDetail{
						Severity: types.SeverityMedium,
						References: []string{
							"https://bugzilla.redhat.com/show_bug.cgi?id=2016142",
						},
						Title:       "mysql-8.0-3520211031142409.f27b74a8",
						Description: "**MySQL 8.0.27**\n\nRelease notes:\n\n    https://dev.mysql.com/doc/relnotes/mysql/8.0/en/news-8-0-27.html",
					},
				},
				{
					key:   []string{"vulnerability-id", "CVE-2021-35623"},
					value: map[string]interface{}{},
				},
			},
		},
		{
			name:    "sad path",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "failed to decode Fedora erratum",
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
