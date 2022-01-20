package osv

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-db/pkg/types"
)

type wantKV struct {
	key   []string
	value interface{}
}

func TestVulnSrc_Update(t *testing.T) {
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
					key: []string{"advisory-detail", "CVE-2018-10895", "pip::Open Source Vulnerability", "qutebrowser"},
					value: types.Advisory{
						VulnerableVersions: []string{">=0, <1.4.1"},
						PatchedVersions:    []string{"1.4.1"},
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2018-10895", "osv-pypi"},
					value: types.VulnerabilityDetail{
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
					key: []string{"advisory-detail", "CVE-2017-18587", "cargo::Open Source Vulnerability", "hyper"},
					value: types.Advisory{
						VulnerableVersions: []string{">=0.0.0-0, <0.9.18", ">=0.10.0, <0.10.2"},
						PatchedVersions:    []string{"0.9.18", "0.10.2"},
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2017-18587", "osv-crates.io"},
					value: types.VulnerabilityDetail{
						Title:       "headers containing newline characters can split messages",
						Description: "Serializing of headers to the socket did not filter the values for newline bytes (`\\r` or `\\n`),\nwhich allowed for header values to split a request or response. People would not likely include\nnewlines in the headers in their own applications, so the way for most people to exploit this\nis if an application constructs headers based on unsanitized user input.\n\nThis issue was fixed by replacing all newline characters with a space during serialization of\na header value.",
						References: []string{
							"https://crates.io/crates/hyper",
							"https://rustsec.org/advisories/RUSTSEC-2017-0002.html",
							"https://github.com/hyperium/hyper/wiki/Security-001",
						},
					},
				},
				{
					key:   []string{"advisory-detail", "CVE-2021-40829"}, // skip GHSA-id
					value: nil,
				},
				{
					key:   []string{"vulnerability-detail", "CVE-2021-40829"}, // skip GHSA-id
					value: nil,
				},
				{
					key:   []string{"vulnerability-id", "CVE-2018-10895"},
					value: map[string]interface{}{},
				},
				{
					key:   []string{"vulnerability-id", "CVE-2017-18587"},
					value: map[string]interface{}{},
				},
				{
					key:   []string{"vulnerability-id", "CVE-2021-40829"}, // skip GHSA-id
					value: nil,
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
			tempDir := t.TempDir()

			err := db.Init(tempDir)
			require.NoError(t, err)
			defer db.Close()

			vulnSrc := NewVulnSrc()
			err = vulnSrc.Update(tt.dir)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.NoError(t, db.Close())

			for _, want := range tt.wantValues {
				if want.value != nil {
					dbtest.JSONEq(t, db.Path(tempDir), want.key, want.value)
				} else {
					dbtest.NoBucket(t, db.Path(tempDir), want.key)
				}

			}
		})
	}
}
