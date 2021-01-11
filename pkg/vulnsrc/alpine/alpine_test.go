package alpine_test

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/dbtest"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/alpine"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
)

func TestVulnSrc_Update(t *testing.T) {
	type want struct {
		key   []string
		value string
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
					key:   []string{"advisory-detail", "CVE-2019-14904", "alpine 3.12", "ansible"},
					value: `{"FixedVersion": "2.9.3-r0"}`,
				},
				{
					key:   []string{"advisory-detail", "CVE-2019-14905", "alpine 3.12", "ansible"},
					value: `{"FixedVersion": "2.9.3-r0"}`,
				},
				{
					key:   []string{"advisory-detail", "CVE-2020-1737", "alpine 3.12", "ansible"},
					value: `{"FixedVersion": "2.9.6-r0"}`,
				},
			},
		},
		{
			name:    "sad path",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "failed to decode Alpine advisory",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()

			err := db.Init(tempDir)
			require.NoError(t, err)

			vs := alpine.NewVulnSrc()
			err = vs.Update(tt.dir)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			} else {
				require.NoError(t, err)
			}

			require.NoError(t, db.Close())

			for _, want := range tt.wantValues {
				dbtest.JSONEq(t, db.Path(tempDir), want.key, want.value)
			}
		})
	}
}
