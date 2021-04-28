package glad_test

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/glad"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			name: "happy path go",
			dir:  filepath.Join("testdata", "happy"),
			wantValues: []want{
				{
					key:   []string{"advisory-detail", "CVE-2016-1905", "go::GitLab Advisory Database Go", "k8s.io/kubernetes"},
					value: `{"PatchedVersions":["v1.2.0"],"VulnerableVersions":["\u003cv1.2.0"]}`,
				},
			},
		},
		{
			name: "happy path maven",
			dir:  filepath.Join("testdata", "happy"),
			wantValues: []want{
				{
					key:   []string{"advisory-detail", "CVE-2018-1196", "maven::GitLab Advisory Database Maven", "org.springframework.boot:spring-boot"},
					value: `{"PatchedVersions":["1.5.10.RELEASE"],"VulnerableVersions":["(,1.5.10)"]}`},
			},
		},
		{
			name:    "sad path",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "failed to decode GLAD",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()

			err := db.Init(tempDir)
			require.NoError(t, err)

			vs := glad.NewVulnSrc()
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