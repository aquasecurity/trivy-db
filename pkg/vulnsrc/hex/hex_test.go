package hex_test

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/hex"
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
					Key: []string{
						"data-source",
						"erlang::Open Source Vulnerabilities (Hex)",
					},
					Value: types.DataSource{
						ID:   vulnerability.OSV,
						Name: "Open Source Vulnerabilities (Hex)",
						URL:  "https://osv.dev/list?ecosystem=Hex",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2026-56813",
						"erlang::Open Source Vulnerabilities (Hex)",
						"plug",
					},
					Value: types.Advisory{
						VendorIDs: []string{
							"GHSA-wpmj-jh88-rpgm",
							"EEF-CVE-2026-56813",
						},
						PatchedVersions: []string{
							"1.16.6",
							"1.17.4",
							"1.18.5",
							"1.19.5",
							"1.20.3",
						},
						VulnerableVersions: []string{
							">=0.1.0, <1.16.6",
							">=1.17.0, <1.17.4",
							">=1.18.0, <1.18.5",
							">=1.19.0, <1.19.5",
							">=1.20.0, <1.20.3",
						},
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2026-56813",
						"osv",
					},
					Value: types.VulnerabilityDetail{
						Title:         "Cookie attribute injection in Plug.Conn.Cookies.encode/2",
						Description:   "## Summary\n\nImproper Neutralization of Parameter/Argument Delimiters vulnerability in elixir-plug plug allows an attacker to inject or override HTTP cookie attributes.\n\nThe Plug.Conn.Cookies.encode/2 function in lib/plug/conn/cookies.ex builds the Set-Cookie response header by interpolating the cookie value and its path, domain, same\\_site, and extra attributes directly into the header without neutralizing the ';' delimiter that separates cookie attributes.\n\nAn application that places attacker-controlled data into a cookie value or attribute (for example via Plug.Conn.put\\_resp\\_cookie/4 when reflecting a username or preference) lets an attacker inject a ';' to append or override cookie attributes (such as Domain and Path scope, or dropping the Secure and HttpOnly flags), enabling cookie tossing and session fixation. Carriage return, line feed, and null bytes are rejected by Plug.Conn header validation, so HTTP response splitting is not possible, but attribute injection through ';' is not prevented.\n\nThis issue affects plug: from 0.1.0 before 1.16.6, from 1.17.0 before 1.17.4, from 1.18.0 before 1.18.5, from 1.19.0 before 1.19.5, from 1.20.0 before 1.20.3.\n\n## Workarounds\n\nValidate or reject the ';' delimiter in any untrusted data before passing it as a cookie value or attribute to Plug.Conn.put\\_resp\\_cookie/4 or Plug.Conn.Cookies.encode/2. Carriage return, line feed, and null bytes are already rejected by Plug.Conn header validation.",
						CvssVectorV40: "CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:L/SA:N",
						CvssScoreV40:  2.1,
						References: []string{
							"https://github.com/elixir-plug/plug/security/advisories/GHSA-wpmj-jh88-rpgm",
							"https://cna.erlef.org/cves/CVE-2026-56813.html",
							"https://github.com/elixir-plug/plug/commit/c6575800b2c4e15af1904df87522ca8a23da020c",
							"https://hex.pm/packages/plug",
						},
						LastModifiedDate: utils.MustTimeParse("2026-09-08T03:30:11.134111522Z"),
						PublishedDate:    utils.MustTimeParse("2026-07-10T12:51:08.758Z"),
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2026-56813",
					},
					Value: map[string]any{},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2017-20166",
						"erlang::Open Source Vulnerabilities (Hex)",
						"ecto",
					},
					Value: types.Advisory{
						VendorIDs: []string{
							"GHSA-2xxx-fhc8-9qvq",
						},
						PatchedVersions: []string{
							"2.2.1",
						},
						VulnerableVersions: []string{
							">=2.2.0, <2.2.1",
						},
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2017-20166",
						"osv",
					},
					Value: types.VulnerabilityDetail{
						Title:        "Ecto missing `is_nil` requirement",
						Description:  "Ecto will not raise on queries with non-explicit nil comparisons (ie if they aren't checked with `is_nil`).",
						CvssVectorV3: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
						CvssScoreV3:  9.8,
						References: []string{
							"https://nvd.nist.gov/vuln/detail/CVE-2017-20166",
							"https://github.com/elixir-ecto/ecto/pull/2125",
							"https://github.com/elixir-ecto/ecto/commit/db55b0cba6525c24ebddc88ef9ae0c1c00620250",
							"https://github.com/elixir-ecto/ecto",
							"https://groups.google.com/forum/#!topic/elixir-ecto/0m4NPfg_MMU",
						},
						LastModifiedDate: utils.MustTimeParse("2026-07-08T06:00:56.101837223Z"),
						PublishedDate:    utils.MustTimeParse("2022-04-12T19:42:45Z"),
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2017-20166",
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
			vs := hex.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
			})
		})
	}
}
