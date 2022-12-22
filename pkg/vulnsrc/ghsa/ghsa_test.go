package ghsa

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
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
					Key: []string{"data-source", "composer::GitHub Security Advisory Composer"},
					Value: types.DataSource{
						ID:   vulnerability.GHSA,
						Name: "GitHub Security Advisory Composer",
						URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Acomposer",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2019-19745", "composer::GitHub Security Advisory Composer", "contao/core-bundle"},
					Value: types.Advisory{
						PatchedVersions:    []string{"4.8.6", "4.4.46"},
						VulnerableVersions: []string{"\u003e= 4.5.0, \u003c 4.8.6", "\u003e= 4.0.0, \u003c 4.4.46"},
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2019-19745", ghsaDir},
					Value: types.VulnerabilityDetail{
						ID:          "CVE-2019-19745",
						Title:       "Unrestricted file uploads in Contao",
						Description: "### Impact\n\nA back end user with access to the form generator can upload arbitrary files and execute them on the server.\n\n### Patches\n\nUpdate to Contao 4.4.46 or 4.8.6.\n\n### Workarounds\n\nConfigure your web server so it does not execute PHP files and other scripts in the Contao file upload directory.\n\n### References\n\nhttps://contao.org/en/security-advisories/unrestricted-file-uploads.html\n\n### For more information\n\nIf you have any questions or comments about this advisory, open an issue in [contao/contao](https://github.com/contao/contao/issues/new/choose).",
						References: []string{
							"https://github.com/contao/contao/security/advisories/GHSA-wjx8-cgrm-hh8p",
							"https://nvd.nist.gov/vuln/detail/CVE-2019-19745",
							"https://contao.org/en/news.html",
							"https://contao.org/en/security-advisories/unrestricted-file-uploads.html",
							"https://github.com/FriendsOfPHP/security-advisories/blob/master/contao/core-bundle/CVE-2019-19745.yaml",
							"https://github.com/advisories/GHSA-wjx8-cgrm-hh8p",
						},
						Severity:     types.SeverityHigh,
						CvssScoreV3:  8.8,
						CvssVectorV3: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2019-19745"},
					Value: map[string]interface{}{},
				},
				{
					Key: []string{"data-source", "maven::GitHub Security Advisory Maven"},
					Value: types.DataSource{
						ID:   vulnerability.GHSA,
						Name: "GitHub Security Advisory Maven",
						URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Amaven",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2018-1196", "maven::GitHub Security Advisory Maven", "org.springframework.boot:spring-boot"},
					Value: types.Advisory{
						PatchedVersions:    []string{"1.5.10"},
						VulnerableVersions: []string{"\u003e= 1.5.0, \u003c 1.5.10"},
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2018-1196", ghsaDir},
					Value: types.VulnerabilityDetail{
						ID:          "CVE-2018-1196",
						Title:       "Moderate severity vulnerability that affects org.springframework.boot:spring-boot",
						Description: "Spring Boot supports an embedded launch script that can be used to easily run the application as a systemd or init.d linux service. The script included with Spring Boot 1.5.9 and earlier and 2.0.0.M1 through 2.0.0.M7 is susceptible to a symlink attack which allows the \"run_user\" to overwrite and take ownership of any file on the same system. In order to instigate the attack, the application must be installed as a service and the \"run_user\" requires shell access to the server. Spring Boot application that are not installed as a service, or are not using the embedded launch script are not susceptible.",
						References: []string{
							"https://nvd.nist.gov/vuln/detail/CVE-2018-1196",
							"https://github.com/advisories/GHSA-xx65-cc7g-9pfp",
							"https://pivotal.io/security/cve-2018-1196",
						},
						Severity:     types.SeverityMedium,
						CvssScoreV3:  5.9,
						CvssVectorV3: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2018-1196"},
					Value: map[string]interface{}{},
				},
				{
					Key: []string{"data-source", "npm::GitHub Security Advisory Npm"},
					Value: types.DataSource{
						ID:   vulnerability.GHSA,
						Name: "GitHub Security Advisory Npm",
						URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2018-3745", "npm::GitHub Security Advisory Npm", "atob"},
					Value: types.Advisory{
						PatchedVersions:    []string{"2.1.0"},
						VulnerableVersions: []string{"\u003c 2.1.0"},
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2018-3745", ghsaDir},
					Value: types.VulnerabilityDetail{
						ID:          "CVE-2018-3745",
						Title:       "Out-of-bounds Read in atob",
						Description: "Versions of `atob` before 2.1.0  uninitialized Buffers when number is passed in input on Node.js 4.x and below.\n\n\n## Recommendation\n\nUpdate to version 2.1.0 or later.",
						References: []string{
							"https://nvd.nist.gov/vuln/detail/CVE-2018-3745",
							"https://hackerone.com/reports/321686",
							"https://github.com/advisories/GHSA-8w4h-3cm3-2pm2",
							"https://www.npmjs.com/advisories/646",
						},
						Severity: types.SeverityMedium,
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2018-3745"},
					Value: map[string]interface{}{},
				},
				{
					Key: []string{"data-source", "nuget::GitHub Security Advisory Nuget"},
					Value: types.DataSource{
						ID:   vulnerability.GHSA,
						Name: "GitHub Security Advisory Nuget",
						URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anuget",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2019-1010113", "nuget::GitHub Security Advisory Nuget", "CLEditor"},
					Value: types.Advisory{
						VulnerableVersions: []string{"\u003c= 1.4.5"},
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2019-1010113", ghsaDir},
					Value: types.VulnerabilityDetail{
						ID:          "CVE-2019-1010113",
						Title:       "Moderate severity vulnerability that affects CLEditor",
						Description: "Premium Software CLEditor 1.4.5 and earlier is affected by: Cross Site Scripting (XSS). The impact is: An attacker might be able to inject arbitrary html and script code into the web site. The component is: jQuery plug-in. The attack vector is: the victim must open a crafted href attribute of a link (A) element.",
						References: []string{
							"https://nvd.nist.gov/vuln/detail/CVE-2019-1010113",
						},
						Severity: types.SeverityMedium,
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2019-1010113"},
					Value: map[string]interface{}{},
				},
				{
					Key: []string{"data-source", "pip::GitHub Security Advisory Pip"},
					Value: types.DataSource{
						ID:   vulnerability.GHSA,
						Name: "GitHub Security Advisory Pip",
						URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2018-14574", "pip::GitHub Security Advisory Pip", "django"},
					Value: types.Advisory{
						PatchedVersions:    []string{"2.0.8", "1.11.15"},
						VulnerableVersions: []string{"\u003e= 2.0, \u003c 2.0.8", "\u003e= 1.11.0, \u003c 1.11.15"},
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2018-14574", ghsaDir},
					Value: types.VulnerabilityDetail{
						ID:          "CVE-2018-14574",
						Title:       "Moderate severity vulnerability that affects django",
						Description: "django.middleware.common.CommonMiddleware in Django 1.11.x before 1.11.15 and 2.0.x before 2.0.8 has an Open Redirect.",
						References: []string{
							"https://nvd.nist.gov/vuln/detail/CVE-2018-14574",
							"https://access.redhat.com/errata/RHSA-2019:0265",
							"https://github.com/advisories/GHSA-5hg3-6c2f-f3wr",
							"https://usn.ubuntu.com/3726-1/",
							"https://www.debian.org/security/2018/dsa-4264",
							"https://www.djangoproject.com/weblog/2018/aug/01/security-releases/",
							"http://www.securityfocus.com/bid/104970",
							"http://www.securitytracker.com/id/1041403",
						},
						Severity:     types.SeverityMedium,
						CvssScoreV3:  6.1,
						CvssVectorV3: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2018-14574"},
					Value: map[string]interface{}{},
				},
				{
					Key: []string{"data-source", "rubygems::GitHub Security Advisory Rubygems"},
					Value: types.DataSource{
						ID:   vulnerability.GHSA,
						Name: "GitHub Security Advisory Rubygems",
						URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Arubygems",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2018-16477", "rubygems::GitHub Security Advisory Rubygems", "activestorage"},
					Value: types.Advisory{
						PatchedVersions:    []string{"5.2.1.1"},
						VulnerableVersions: []string{"\u003e= 5.2.0, \u003c= 5.2.1.0"},
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2018-16477", ghsaDir},
					Value: types.VulnerabilityDetail{
						ID:          "CVE-2018-16477",
						Title:       "High severity vulnerability that affects activestorage",
						Description: "A bypass vulnerability in Active Storage >= 5.2.0 for Google Cloud Storage and Disk services allow an attacker to modify the `content-disposition` and `content-type` parameters which can be used in with HTML files and have them executed inline. Additionally, if combined with other techniques such as cookie bombing and specially crafted AppCache manifests, an attacker can gain access to private signed URLs within a specific storage path.",
						References: []string{
							"https://nvd.nist.gov/vuln/detail/CVE-2018-16477",
							"https://github.com/advisories/GHSA-7rr7-rcjw-56vj",
							"https://groups.google.com/d/msg/rubyonrails-security/3KQRnXDIuLg/mByx5KkqBAAJ",
							"https://weblog.rubyonrails.org/2018/11/27/Rails-4-2-5-0-5-1-5-2-have-been-released/",
						},
						Severity:     types.SeverityMedium,
						CvssScoreV3:  6.5,
						CvssVectorV3: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2018-16477"},
					Value: map[string]interface{}{},
				},
				{
					Key: []string{"data-source", "cargo::GitHub Security Advisory Rust"},
					Value: types.DataSource{
						ID:   vulnerability.GHSA,
						Name: "GitHub Security Advisory Rust",
						URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Arust",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2020-26235", "cargo::GitHub Security Advisory Rust", "time"},
					Value: types.Advisory{
						PatchedVersions:    []string{"0.2.23"},
						VulnerableVersions: []string{"\u003e= 0.2.7, \u003c 0.2.23"},
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2020-26235", ghsaDir},
					Value: types.VulnerabilityDetail{
						ID:          "CVE-2020-26235",
						Title:       "Segmentation fault in time",
						Description: "### Impact\n\nUnix-like operating systems may segfault due to dereferencing a dangling pointer in specific circumstances. This requires an environment variable to be set in a different thread than the affected functions. This may occur without the user's knowledge, notably in a third-party library.\n\nThe affected functions from time 0.2.7 through 0.2.22 are:\n\n- `time::UtcOffset::local_offset_at`\n- `time::UtcOffset::try_local_offset_at`\n- `time::UtcOffset::current_local_offset`\n- `time::UtcOffset::try_current_local_offset`\n- `time::OffsetDateTime::now_local`\n- `time::OffsetDateTime::try_now_local`\n\nThe affected functions in time 0.1 (all versions) are:\n\n- `at`\n- `at_utc`\n- `now`\n\nNon-Unix targets (including Windows and wasm) are unaffected.\n\n### Patches\n\nIn some versions of time`, the internal method that determines the local offset has been modified to always return `None` on the affected operating systems. This has the effect of returning an `Err` on the `try_*` methods and `UTC` on the non-`try_*` methods. In later versions, `time` will attempt to determine the number of threads running in the process. If the process is single-threaded, the call will proceed as its safety invariant is upheld.\n\nUsers and library authors with time in their dependency tree must perform `cargo update`, which will pull in the updated, unaffected code.\n\nUsers of time 0.1 do not have a patch and must upgrade to an unaffected version: time 0.2.23 or greater or the 0.3 series.\n\n### Workarounds\n\nLibrary authors must ensure that the program only has one running thread at the time of calling any affected method. Binary authors may do the same and/or ensure that no other thread is actively mutating the environment.\n\n### References\n\ntime-rs/time#293",
						References: []string{
							"https://github.com/time-rs/time/security/advisories/GHSA-wcg3-cvx6-7396",
							"https://nvd.nist.gov/vuln/detail/CVE-2020-26235",
							"https://github.com/time-rs/time/issues/293",
							"https://rustsec.org/advisories/RUSTSEC-2020-0071.html",
							"https://crates.io/crates/time/0.2.23",
							"https://github.com/advisories/GHSA-wcg3-cvx6-7396",
						},
						Severity:     types.SeverityMedium,
						CvssScoreV3:  6.2,
						CvssVectorV3: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2020-26235"},
					Value: map[string]interface{}{},
				},
				///

				{
					Key: []string{"data-source", "erlang::GitHub Security Advisory Erlang"},
					Value: types.DataSource{
						ID:   vulnerability.GHSA,
						Name: "GitHub Security Advisory Erlang",
						URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Aerlang",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2017-1000212", "erlang::GitHub Security Advisory Erlang", "alchemist.vim"},
					Value: types.Advisory{
						PatchedVersions:    []string{"1.3.2"},
						VulnerableVersions: []string{"\u003c= 1.3.1"},
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2017-1000212", ghsaDir},
					Value: types.VulnerabilityDetail{
						ID:          "CVE-2017-1000212",
						Title:       "alchemist.vim vulnerable to remote code execution",
						Description: "Elixir's vim plugin, alchemist.vim is vulnerable to remote code execution in the bundled alchemist-server. A malicious website can execute requests against an ephemeral port on localhost that are then evaluated as elixir code.",
						References: []string{
							"https://nvd.nist.gov/vuln/detail/CVE-2017-1000212",
							"https://github.com/tonini/alchemist-server/issues/14",
							"https://github.com/tonini/alchemist-server/pull/16",
							"https://elixirforum.com/t/static-and-session-security-fixes-for-plug/3913",
							"https://github.com/advisories/GHSA-6x65-vqp7-5r63",
						},
						Severity:     types.SeverityCritical,
						CvssScoreV3:  9.8,
						CvssVectorV3: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2017-1000212"},
					Value: map[string]interface{}{},
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
			wantErr: "failed to decode GHSA",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
			})
		})
	}
}
