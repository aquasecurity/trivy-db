package k8svulndb_test

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/k8svulndb"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
)

func TestVulnSrc_Update(t *testing.T) {
	tests := []struct {
		name    string
		dir     string
		want    []vulnsrctest.WantValues
		wantErr string
	}{
		{
			name: "happy path fixed version",
			dir:  "testdata/happy-fixed",
			want: []vulnsrctest.WantValues{
				{
					Key: []string{
						"advisory-detail",
						"CVE-2023-2727",
						"k8s::Official Kubernetes CVE Feed",
						"k8s.io/apiserver",
					},
					Value: types.Advisory{
						PatchedVersions:    []string{"1.24.14"},
						VulnerableVersions: []string{">=1.24.0, <1.24.14"},
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2023-2727",
						string(vulnerability.Kubernetes),
					},
					Value: types.VulnerabilityDetail{
						Title:        "Bypassing policies imposed by the ImagePolicyWebhook and bypassing mountable secrets policy imposed by the ServiceAccount admission plugin",
						Description:  "Users may be able to launch containers using images that are restricted by ImagePolicyWebhook when using ephemeral containers. Kubernetes clusters are only affected if the ImagePolicyWebhook admission plugin is used together with ephemeral containers.",
						References:   []string{"https: //www.cve.org/cverecord?id=CVE-2023-2727"},
						CvssVectorV3: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N",
						CvssScoreV3:  6.5,
					},
				},
			},
		},
		{
			name: "happy path affected version",
			dir:  "testdata/happy",
			want: []vulnsrctest.WantValues{
				{
					Key: []string{
						"advisory-detail",
						"CVE-2023-2727",
						"k8s::Official Kubernetes CVE Feed",
						"k8s.io/apiserver",
					},
					Value: types.Advisory{
						VulnerableVersions: []string{">=1.24.0, <=1.24.14"},
					},
				},
			},
		},
		{
			name:    "sad path",
			dir:     filepath.Join("testdata", "broken"),
			wantErr: "JSON decode error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := k8svulndb.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.want,
				WantErr:    tt.wantErr,
			})
		})
	}
}
