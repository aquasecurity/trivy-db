package epel

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
					key: []string{"advisory-detail", "CVE-2022-0217", "epel 8", "prosody"},
					value: types.Advisory{
						FixedVersion: "0.11.12-1.el8",
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2022-0217", string(vulnerability.EPEL)},
					value: types.VulnerabilityDetail{
						Severity: types.SeverityMedium,
						References: []string{
							"https://bugzilla.redhat.com/show_bug.cgi?id=2040350",
							"https://bugzilla.redhat.com/show_bug.cgi?id=2040639",
							"https://bugzilla.redhat.com/show_bug.cgi?id=2040641",
						},
						Title:       "prosody-0.11.12-1.el8",
						Description: "# Prosody 0.11.12\n\nUpstream is pleased to announce a new minor release from their stable branch.\n\nThis is a security release that addresses a denial-of-service vulnerability in Prosody’s mod_websocket. For more information, refer to the [20220113 advisory](https://prosody.im/security/advisory_20220113/).\n\n## Security\n  * util.xml: Do not allow doctypes, comments or processing instructions\n",
					},
				},
				{
					key:   []string{"vulnerability-id", "CVE-2022-0217"},
					value: map[string]interface{}{},
				},
			},
		},
		{
			name:    "sad path",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "failed to decode EPEL erratum",
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
