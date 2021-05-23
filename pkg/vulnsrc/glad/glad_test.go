package glad_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/glad"
)

func TestVulnSrc_Update(t *testing.T) {
	type wantKV struct {
		key   []string
		value interface{}
	}
	tests := []struct {
		name       string
		dir        string
		wantValues []wantKV
		wantErr    string
	}{
		{
			name: "happy path",
			dir:  filepath.Join("testdata", "happy"),
			wantValues: []wantKV{
				{
					key: []string{"advisory-detail", "CVE-2016-1905", "go::GitLab Advisory Database", "k8s.io/kubernetes"},
					value: types.Advisory{
						PatchedVersions:    []string{"v1.2.0"},
						VulnerableVersions: []string{"<v1.2.0"},
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2018-1196", "maven::GitLab Advisory Database", "org.springframework.boot:spring-boot"},
					value: types.Advisory{
						PatchedVersions:    []string{"1.5.10.RELEASE"},
						VulnerableVersions: []string{"(,1.5.10)"},
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2016-1905", "glad"},
					value: types.VulnerabilityDetail{
						ID:          "CVE-2016-1905",
						Title:       "Improper Access Control",
						Description: "The API server in Kubernetes does not properly check admission control, which allows remote authenticated users to access additional resources via a crafted patched object.",
						References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2016-1905"},
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2018-1196", "glad"},
					value: types.VulnerabilityDetail{
						ID:          "CVE-2018-1196",
						Title:       "Symlink privilege escalation attack via Spring Boot launch script",
						Description: "Spring Boot supports an embedded launch script that can be used to easily run the application as a systemd or init.d linux service. The script included with Spring Boot is susceptible to a symlink attack which allows the `run_user` to overwrite and take ownership of any file on the same system. In order to instigate the attack, the application must be installed as a service and the `run_user` requires shell access to the server.",
						References:  []string{"https://pivotal.io/security/cve-2018-1196"},
					},
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

			for _, want := range tt.wantValues {
				dbtest.JSONEq(t, db.Path(tempDir), want.key, want.value)
			}
		})
	}
}
