package osv

import (
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
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
					Key: []string{"data-source", "pip::Open Source Vulnerability"},
					Value: types.DataSource{
						ID:   vulnerability.OSV,
						Name: "Python Packaging Advisory Database",
						URL:  "https://github.com/pypa/advisory-db",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2018-10895", "pip::Open Source Vulnerability", "qutebrowser"},
					Value: types.Advisory{
						VulnerableVersions: []string{">=0, <1.4.1"},
						PatchedVersions:    []string{"1.4.1"},
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2018-10895", string(vulnerability.OSV)},
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
					Key:   []string{"vulnerability-id", "CVE-2018-10895"},
					Value: map[string]interface{}{},
				},
			},
			noBuckets: [][]string{ //skip GHSA-id
				{"advisory-detail", "CVE-2021-40829"},
				{"vulnerability-detail", "CVE-2021-40829"},
				{"vulnerability-id", "CVE-2021-40829"},
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
			vs := NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
				NoBuckets:  tt.noBuckets,
			})
		})
	}
}
