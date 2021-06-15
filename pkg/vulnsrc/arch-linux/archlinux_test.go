package archlinux

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-db/pkg/types"
)

func TestVulnSrc_Update(t *testing.T) {
	type want struct {
		key   []string
		value types.Advisory
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
					key: []string{"advisory-detail", "CVE-2019-11479", "archlinux", "linux-lts"},
					value: types.Advisory{
						FixedVersion:    "4.19.52-1",
						AffectedVersion: "4.19.51-1",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2019-11478", "archlinux", "linux-lts"},
					value: types.Advisory{
						FixedVersion:    "4.19.52-1",
						AffectedVersion: "4.19.51-1",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2019-11477", "archlinux", "linux-lts"},
					value: types.Advisory{
						FixedVersion:    "4.19.52-1",
						AffectedVersion: "4.19.51-1",
					},
				},
			},
		},
		{
			name:    "sad path",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "failed to decode arch linux json",
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
			for _, want := range tt.wantValues {
				dbtest.JSONEq(t, db.Path(tempDir), want.key, want.value)
			}
		})
	}
}
