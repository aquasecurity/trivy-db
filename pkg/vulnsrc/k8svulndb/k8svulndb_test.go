package k8svulndb_test

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/k8svulndb"
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
						Severity:           types.SeverityHigh,
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
