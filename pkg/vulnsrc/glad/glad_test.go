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
			name: "happy path conan",
			dir:  filepath.Join("testdata"),
			wantValues: []want{
				{
					key:   []string{"advisory-detail", "CVE-2020-14150", "conan::GitLab Advisory Database Conan", "bison"},
					value: `{"PatchedVersions":["3.7.1"],"VulnerableVersions":["\u003c3.5.4"]}`,
				},
			},
		},
		{
			name: "happy path gem",
			dir:  filepath.Join("testdata"),
			wantValues: []want{
				{
					key:   []string{"advisory-detail", "OSVDB-112347", "rubygems::GitLab Advisory Database Gem", "activejob"},
					value: `{"PatchedVersions":["4.2.0.beta2"],"VulnerableVersions":["=4.2.0.beta1"]}`},
			},
		},
		{
			name: "happy path go",
			dir:  filepath.Join("testdata"),
			wantValues: []want{
				{
					key:   []string{"advisory-detail", "CVE-2016-1905", "go::GitLab Advisory Database Go", "k8s.io/kubernetes"},
					value: `{"PatchedVersions":["v1.2.0"],"VulnerableVersions":["\u003cv1.2.0"]}`,
				},
			},
		},
		{
			name: "happy path maven",
			dir:  filepath.Join("testdata"),
			wantValues: []want{
				{
					key:   []string{"advisory-detail", "CVE-2018-1196", "maven::GitLab Advisory Database Maven", "org.springframework.boot:spring-boot"},
					value: `{"PatchedVersions":["1.5.10.RELEASE"],"VulnerableVersions":["(,1.5.10)"]}`},
			},
		},
		{
			name: "happy path npm",
			dir:  filepath.Join("testdata"),
			wantValues: []want{
				{
					key:   []string{"advisory-detail", "CVE-2019-10742", "npm::GitLab Advisory Database Npm", "axios"},
					value: `{"PatchedVersions":["0.18.1"],"VulnerableVersions":["\u003c=0.18.0"]}`,
				},
			},
		},
		{
			name: "happy path nuget",
			dir:  filepath.Join("testdata"),
			wantValues: []want{
				{
					key:   []string{"advisory-detail", "CVE-2020-1108", "nuget::GitLab Advisory Database Nuget", "powershell"},
					value: `{"PatchedVersions":["7.1.0"],"VulnerableVersions":["[7.0]"]}`,
				},
			},
		},
		{
			name: "happy path packagist",
			dir:  filepath.Join("testdata"),
			wantValues: []want{
				{
					key:   []string{"advisory-detail", "GMS-2018-25", "composer::GitLab Advisory Database Packagist", "adodb/adodb-php"},
					value: `{"PatchedVersions":["v5.20.11"],"VulnerableVersions":["\u003c5.20.11"]}`,
				},
			},
		},
		{
			name: "happy path pypi",
			dir:  filepath.Join("testdata"),
			wantValues: []want{
				{
					key:   []string{"advisory-detail", "CVE-2020-13254", "pip::GitLab Advisory Database PyPI", "Django"},
					value: `{"PatchedVersions":["2.2.13","3.0.7"],"VulnerableVersions":["\u003e=2.2,\u003c2.2.13||\u003e=3.0,\u003c3.0.7"]}`,
				},
			},
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
