package alma

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
					key: []string{"advisory-detail", "CVE-2021-27918", "alma 8", "go-toolset"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-27918", "alma 8", "golang"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-27918", "alma 8", "golang-bin"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-27918", "alma 8", "golang-docs"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-27918", "alma 8", "golang-misc"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-27918", "alma 8", "golang-race"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-27918", "alma 8", "golang-src"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-27918", "alma 8", "golang-tests"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-27918", "alma 8", "go-toolset"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-27918", "alma 8", "golang"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-27918", "alma 8", "golang-bin"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-27918", "alma 8", "golang-docs"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-27918", "alma 8", "golang-misc"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-27918", "alma 8", "golang-race"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-27918", "alma 8", "golang-src"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-27918", "alma 8", "golang-tests"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-31525", "alma 8", "go-toolset"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-31525", "alma 8", "golang"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-31525", "alma 8", "golang-bin"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-31525", "alma 8", "golang-docs"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-31525", "alma 8", "golang-misc"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-31525", "alma 8", "golang-race"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-31525", "alma 8", "golang-src"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-31525", "alma 8", "golang-tests"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-33196", "alma 8", "go-toolset"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-33196", "alma 8", "golang"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-33196", "alma 8", "golang-bin"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-33196", "alma 8", "golang-docs"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-33196", "alma 8", "golang-misc"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-33196", "alma 8", "golang-race"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-33196", "alma 8", "golang-src"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-33196", "alma 8", "golang-tests"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-34558", "alma 8", "go-toolset"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-34558", "alma 8", "golang"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-34558", "alma 8", "golang-bin"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-34558", "alma 8", "golang-docs"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-34558", "alma 8", "golang-misc"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-34558", "alma 8", "golang-race"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-34558", "alma 8", "golang-src"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-34558", "alma 8", "golang-tests"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
			},
		},
		{
			name:    "sad path",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "failed to decode Alma erratum",
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
