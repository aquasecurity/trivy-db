package osv_test

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/osv"
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
						"pip::Python Packaging Advisory Database",
					},
					Value: types.DataSource{
						ID:   vulnerability.OSV,
						Name: "Python Packaging Advisory Database",
						URL:  "https://github.com/pypa/advisory-db",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2018-10895",
						"pip::Python Packaging Advisory Database",
						"qutebrowser",
					},
					Value: types.Advisory{
						VendorIDs: []string{
							"GHSA-wgmx-52ph-qqcw",
							"PYSEC-2018-27",
						},
						VulnerableVersions: []string{"<1.4.1"},
						PatchedVersions:    []string{"1.4.1"},
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2018-10895",
						string(vulnerability.OSV),
					},
					Value: types.VulnerabilityDetail{
						Description: "qutebrowser before version 1.4.1 is vulnerable to a cross-site request forgery flaw that allows websites to access 'qute://*' URLs. A malicious website could exploit this to load a 'qute://settings/set' URL, which then sets 'editor.command' to a bash script, resulting in arbitrary code execution.",
						References: []string{
							"https://github.com/qutebrowser/qutebrowser/commit/43e58ac865ff862c2008c510fc5f7627e10b4660",
							"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2018-10895",
							"http://www.openwall.com/lists/oss-security/2018/07/11/7",
							"https://github.com/advisories/GHSA-wgmx-52ph-qqcw",
						},
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2018-10895",
					},
					Value: map[string]interface{}{},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2013-4251",
					},
					Value: map[string]interface{}{},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2023-37276",
						"pip::Python Packaging Advisory Database",
						"aiohttp",
					},
					Value: types.Advisory{
						VendorIDs: []string{
							"GHSA-45c4-8wx5-qw6w",
							"PYSEC-2023-120",
						},
						VulnerableVersions: []string{
							"<=3.8.4",
							"=4.0.1",
						},
					},
				},
			},
			noBuckets: [][]string{
				// skip withdrawn
				{
					"vulnerability-id",
					"CVE-2023-31655",
				},
				{
					"advisory-detail",
					"CVE-2023-31655",
				},
				{
					"vulnerability-detail",
					"CVE-2023-31655",
				},
			},
		},
		{
			name:    "sad path",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "JSON decode error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataSources := map[types.Ecosystem]types.DataSource{
				vulnerability.Pip: {
					ID:   vulnerability.OSV,
					Name: "Python Packaging Advisory Database",
					URL:  "https://github.com/pypa/advisory-db",
				},
			}
			o := osv.New(".", vulnerability.OSV, dataSources, nil)
			vulnsrctest.TestUpdate(t, o, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
				NoBuckets:  tt.noBuckets,
			})
		})
	}
}
