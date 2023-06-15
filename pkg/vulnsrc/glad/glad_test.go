package glad_test

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/glad"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
)

func TestVulnSrc_Update(t *testing.T) {
	tests := []struct {
		name       string
		dir        string
		wantValues []vulnsrctest.WantValues
		wantErr    string
	}{
		{
			name: "happy path",
			dir:  filepath.Join("testdata", "happy"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"data-source", "maven::GitLab Advisory Database Community"},
					Value: types.DataSource{
						ID:   vulnerability.GLAD,
						Name: "GitLab Advisory Database Community",
						URL:  "https://gitlab.com/gitlab-org/advisories-community",
					},
				},
				{
					Key: []string{"data-source", "conan::GitLab Advisory Database Community"},
					Value: types.DataSource{
						ID:   vulnerability.GLAD,
						Name: "GitLab Advisory Database Community",
						URL:  "https://gitlab.com/gitlab-org/advisories-community",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2018-1196", "maven::GitLab Advisory Database Community", "org.springframework.boot:spring-boot"},
					Value: types.Advisory{
						PatchedVersions:    []string{"1.5.10.RELEASE"},
						VulnerableVersions: []string{"(,1.5.10)"},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2020-13574", "conan::GitLab Advisory Database Community", "gsoap"},
					Value: types.Advisory{
						VulnerableVersions: []string{"=2.8.107"},
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2018-1196", "glad"},
					Value: types.VulnerabilityDetail{
						ID:          "CVE-2018-1196",
						Title:       "Symlink privilege escalation attack via Spring Boot launch script",
						Description: "Spring Boot supports an embedded launch script that can be used to easily run the application as a systemd or init.d linux service. The script included with Spring Boot is susceptible to a symlink attack which allows the `run_user` to overwrite and take ownership of any file on the same system. In order to instigate the attack, the application must be installed as a service and the `run_user` requires shell access to the server.",
						References:  []string{"https://pivotal.io/security/cve-2018-1196"},
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2020-13574", "glad"},
					Value: types.VulnerabilityDetail{
						ID:          "CVE-2020-13574",
						Title:       "NULL Pointer Dereference",
						Description: "A denial-of-service vulnerability exists in the WS-Security plugin functionality of Genivia gSOAP. A specially crafted SOAP request can lead to denial of service. An attacker can send an HTTP request to trigger this vulnerability.",
						References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2020-13574"},
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
			vs := glad.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
			})
		})
	}
}
