package glad_test

import (
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/glad"
)

func TestVulnSrc_Update(t *testing.T) {
	type want struct {
		key        []string
		goldenFile string
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
					key:        []string{"advisory-detail", "CVE-2016-1905", "go::GitLab Advisory Database", "k8s.io/kubernetes"},
					goldenFile: filepath.Join("testdata", "golden", "advisory", "CVE-2016-1905.json"),
				},
				{
					key:        []string{"advisory-detail", "CVE-2018-1196", "maven::GitLab Advisory Database", "org.springframework.boot:spring-boot"},
					goldenFile: filepath.Join("testdata", "golden", "advisory", "CVE-2018-1196.json"),
				},
				{
					key:        []string{"vulnerability-detail", "CVE-2016-1905", "glad"},
					goldenFile: filepath.Join("testdata", "golden", "vulnerability", "CVE-2016-1905.json"),
				},
				{
					key:        []string{"vulnerability-detail", "CVE-2018-1196", "glad"},
					goldenFile: filepath.Join("testdata", "golden", "vulnerability", "CVE-2018-1196.json"),
				},
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
			defer db.Close()

			vs := glad.NewVulnSrc()
			err = vs.Update(tt.dir)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.NoError(t, db.Close())

			for _, wantValue := range tt.wantValues {
				expectedValue, err := ioutil.ReadFile(wantValue.goldenFile)
				require.NoError(t, err)
				dbtest.JSONEq(t, db.Path(tempDir), wantValue.key, string(expectedValue))
			}
		})
	}
}
