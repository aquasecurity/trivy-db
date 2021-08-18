package pypa

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_pypa(t *testing.T) {
	type want struct {
		key   []string
		value types.Advisory
	}
	tests := []struct {
		name      string
		dir       string
		wantValue want
		wantErr   string
	}{
		{
			name: "single range",
			dir:  filepath.Join("testdata", "singlerange"),
			wantValue: want{
				key: []string{"advisory-detail", "CVE-2018-10895", "pypa", "qutebrowser"},
				value: types.Advisory{
					VulnerableVersions: []string{">=0.0.0 <1.4.1"},
				},
			},
		},
		{
			name: "multi range",
			dir:  filepath.Join("testdata", "multirange"),
			wantValue: want{
				key: []string{"advisory-detail", "CVE-2021-33571", "pypa", "django"},
				value: types.Advisory{
					VulnerableVersions: []string{">=2.2 <2.2.24", ">=3.0 <3.1.12", ">=3.2 <3.2.4"},
				},
			},
		},
		{
			name:    "sad path",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "failed to decode pypa json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			tempDir := t.TempDir()

			err := db.Init(tempDir)
			require.NoError(t, err)
			defer db.Close()

			vulnSrc := NewVulnSrc()
			err = vulnSrc.Update(tt.dir)

			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)

			db.Close()

			dbtest.JSONEq(t, db.Path(tempDir), tt.wantValue.key, tt.wantValue.value)
		})
	}
}
