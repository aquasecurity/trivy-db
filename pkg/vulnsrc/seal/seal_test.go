package seal_test

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/seal"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
)

func TestVulnSrc_Update(t *testing.T) {
	tests := []struct {
		name       string
		dir        string
		wantValues []vulnsrctest.WantValues
		noBuckets  [][]string
		wantErr    string
	}{
		{
			name: "happy path",
			dir:  filepath.Join("testdata", "happy"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{
						"data-source",
						"seal redhat 8",
					},
					Value: types.DataSource{
						ID:   vulnerability.Seal,
						Name: "Seal Security Database",
						URL:  "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2019-9924",
						"seal redhat 8",
						"seal-bash",
					},
					Value: types.Advisory{
						PatchedVersions: []string{
							"4.2.46-35.el7_9+sp999",
						},
						VulnerableVersions: []string{
							">=4.2.46-35.el7_9, <4.2.46-35.el7_9+sp999",
						},
					},
				},
				{
					Key: []string{
						"data-source",
						"seal oracle-linux 5",
					},
					Value: types.DataSource{
						ID:   vulnerability.Seal,
						Name: "Seal Security Database",
						URL:  "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2019-9924",
						"seal oracle-linux 5",
						"seal-bash",
					},
					Value: types.Advisory{
						PatchedVersions: []string{
							"4.2.46-35.el7_9+sp999",
						},
						VulnerableVersions: []string{
							">=4.2.46-35.el7_9, <4.2.46-35.el7_9+sp999",
						},
					},
				},
				{
					Key: []string{
						"data-source",
						"seal centos 7",
					},
					Value: types.DataSource{
						ID:   vulnerability.Seal,
						Name: "Seal Security Database",
						URL:  "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2019-9924",
						"seal centos 7",
						"seal-bash",
					},
					Value: types.Advisory{
						PatchedVersions: []string{
							"4.2.46-35.el7_9+sp999",
						},
						VulnerableVersions: []string{
							">=4.2.46-35.el7_9, <4.2.46-35.el7_9+sp999",
						},
					},
				},
				{
					Key: []string{
						"data-source",
						"seal cbl-mariner 1.0",
					},
					Value: types.DataSource{
						ID:   vulnerability.Seal,
						Name: "Seal Security Database",
						URL:  "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2019-9924",
						"seal cbl-mariner 1.0",
						"seal-bash",
					},
					Value: types.Advisory{
						PatchedVersions: []string{
							"4.2.46-35.el7_9+sp999",
						},
						VulnerableVersions: []string{
							">=4.2.46-35.el7_9, <4.2.46-35.el7_9+sp999",
						},
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2019-9924",
						"seal",
					},
					Value: types.VulnerabilityDetail{
						LastModifiedDate: utils.MustTimeParse("2024-11-07T12:21:22.940791Z"),
						PublishedDate:    utils.MustTimeParse("2019-03-07T00:00:00Z"),
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2019-9924",
					},
					Value: map[string]any{},
				},
			},
		},
		{
			name:    "sad path (dir doesn't exist)",
			dir:     filepath.Join("testdata", "badPath"),
			wantErr: "no such file or directory",
		},
		{
			name:    "sad path (failed to decode)",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "json decode error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := seal.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
				NoBuckets:  tt.noBuckets,
			})
		})
	}
}
