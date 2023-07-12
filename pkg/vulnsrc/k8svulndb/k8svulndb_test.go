package k8svulndb_test

import (
	"strings"
	"testing"
	"time"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/k8svulndb"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

func TestVulnSrc_Update(t *testing.T) {
	publishedDate, err := time.Parse(time.RFC3339, "2023-06-13T14:42:06Z")
	if err != nil {
		publishedDate = time.Now()
	}
	severity, err := types.NewSeverity(strings.ToUpper("Medium"))
	if err != nil {
		severity = types.SeverityLow
	}
	tests := []struct {
		name    string
		dir     string
		want    []vulnsrctest.WantValues
		wantErr string
	}{
		{
			name: "happy path",
			dir:  "testdata/happy",
			want: []vulnsrctest.WantValues{
				{
					Key: []string{"data-source", "k8s::The k8s Vulnerability Database"},
					Value: types.DataSource{
						ID:   vulnerability.K8sVulnDB,
						Name: "The k8s Vulnerability Database",
						URL:  "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2023-2727", "k8s::The k8s Vulnerability Database", "k8s.io/kube-apiserver"},
					Value: types.Advisory{
						PatchedVersions:    []string{"1.27.3"},
						VulnerableVersions: []string{"1.27.0, <=1.27.2"},
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2023-2727", string(vulnerability.K8sVulnDB)},
					Value: types.VulnerabilityDetail{
						Description: "CVE-2023-2727: Bypassing policies imposed by the ImagePolicyWebhook admission pluginCVSS Rating: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:NA security issue was discovered in Kubernetes where users may be able to launch containers using images that are restricted by ImagePolicyWebhook when using ephemeral containers. Kubernetes clusters are only affected if the ImagePolicyWebhook admission plugin is used together with ephemeral containers.Am I vulnerable?Clusters are impacted by this vulnerability if all of the following are true:",
						References: []string{
							"https://github.com/kubernetes/kubernetes/issues/118640",
							"https://www.cve.org/cverecord?id=CVE-2023-2727, CVE-2023-2728",
						},
						ID:               "CVE-2023-2727",
						CvssScoreV3:      6.5,
						CvssVector:       "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N",
						Severity:         severity,
						PublishedDate:    &publishedDate,
						LastModifiedDate: &publishedDate,
						Title:            "Bypassing policies imposed by the ImagePolicyWebhook and bypassing mountable secrets policy imposed by the ServiceAccount admission plugin",
					},
				},
			},
		},
		{
			name:    "broken JSON",
			dir:     "testdata/broken",
			wantErr: "JSON decode error",
		},
		{
			name:    "sad path",
			dir:     "./sad",
			wantErr: "no such file or directory",
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
