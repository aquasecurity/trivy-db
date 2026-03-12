package osv_test

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
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
						LastModifiedDate: utils.MustTimeParse("2021-06-10T06:51:37.378319Z"),
						PublishedDate:    utils.MustTimeParse("2018-07-12T12:29:00Z"),
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2018-10895",
					},
					Value: map[string]any{},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2013-4251",
					},
					Value: map[string]any{},
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
				// CVSSv4: advisory with both V3 and V4
				{
					Key: []string{
						"advisory-detail",
						"CVE-2026-21860",
						"pip::Python Packaging Advisory Database",
						"werkzeug",
					},
					Value: types.Advisory{
						VendorIDs: []string{
							"PYSEC-2026-1",
						},
						PatchedVersions:    []string{"3.1.5"},
						VulnerableVersions: []string{"<3.1.5"},
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2026-21860",
						string(vulnerability.OSV),
					},
					Value: types.VulnerabilityDetail{
						Title:         "Werkzeug safe_join() allows Windows special device names with compound extensions",
						Description:   "Werkzeug's `safe_join` function allows path segments with Windows device names that have file extensions or trailing spaces.",
						CvssVectorV3:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
						CvssScoreV3:   5.3,
						CvssVectorV40: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N",
						CvssScoreV40:  6.3,
						References: []string{
							"https://github.com/pallets/werkzeug/security/advisories/GHSA-87hc-h4r5-73f7",
							"https://nvd.nist.gov/vuln/detail/CVE-2026-21860",
						},
						LastModifiedDate: utils.MustTimeParse("2026-02-02T19:57:31Z"),
						PublishedDate:    utils.MustTimeParse("2026-01-08T19:51:21Z"),
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2026-21860",
					},
					Value: map[string]any{},
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
			wantErr: "json decode error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dataSources := map[ecosystem.Type]types.DataSource{
				ecosystem.Pip: {
					ID:   vulnerability.OSV,
					Name: "Python Packaging Advisory Database",
					URL:  "https://github.com/pypa/advisory-db",
				},
			}
			o := osv.New(".", vulnerability.OSV, dataSources)
			vulnsrctest.TestUpdate(t, o, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
				NoBuckets:  tt.noBuckets,
			})
		})
	}
}
