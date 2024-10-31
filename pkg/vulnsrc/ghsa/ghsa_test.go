package ghsa_test

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/ghsa"
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
						"maven::GitHub Security Advisory Maven",
					},
					Value: types.DataSource{
						ID:   vulnerability.GHSA,
						Name: "GitHub Security Advisory Maven",
						URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Amaven",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2018-1196",
						"maven::GitHub Security Advisory Maven",
						"org.springframework.boot:spring-boot",
					},
					Value: types.Advisory{
						VendorIDs: []string{
							"GHSA-xx65-cc7g-9pfp",
						},
						PatchedVersions:    []string{"1.5.10"},
						VulnerableVersions: []string{">=1.5.0, <1.5.10"},
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2018-1196",
						"ghsa",
					},
					Value: types.VulnerabilityDetail{
						Title:       "Moderate severity vulnerability that affects org.springframework.boot:spring-boot",
						Description: "Spring Boot supports an embedded launch script that can be used to easily run the application as a systemd or init.d linux service. The script included with Spring Boot 1.5.9 and earlier and 2.0.0.M1 through 2.0.0.M7 is susceptible to a symlink attack which allows the \"run_user\" to overwrite and take ownership of any file on the same system. In order to instigate the attack, the application must be installed as a service and the \"run_user\" requires shell access to the server. Spring Boot application that are not installed as a service, or are not using the embedded launch script are not susceptible.",
						References: []string{
							"https://nvd.nist.gov/vuln/detail/CVE-2018-1196",
							"https://github.com/advisories/GHSA-xx65-cc7g-9pfp",
							"https://pivotal.io/security/cve-2018-1196",
						},
						Severity:     types.SeverityMedium,
						CvssVectorV3: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
						CvssScoreV3:  5.9,
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2018-1196",
					},
					Value: map[string]interface{}{},
				},
				{
					Key: []string{
						"data-source",
						"maven::GitHub Security Advisory Maven",
					},
					Value: types.DataSource{
						ID:   vulnerability.GHSA,
						Name: "GitHub Security Advisory Maven",
						URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Amaven",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2023-25330",
						"maven::GitHub Security Advisory Maven",
						"com.baomidou:mybatis-plus",
					},
					Value: types.Advisory{
						VendorIDs: []string{
							"GHSA-32qq-m9fh-f74w",
						},
						VulnerableVersions: []string{">=0, <3.5.3.1"},
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2023-25330",
						"maven::GitHub Security Advisory Maven",
						"com.baomidou:mybatis-plus-copy",
					},
					Value: types.Advisory{
						VendorIDs: []string{
							"GHSA-32qq-m9fh-f74w",
						},
						PatchedVersions:    []string{"3.5.0"},
						VulnerableVersions: []string{"<3.5.0"},
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2023-25330",
						"ghsa",
					},
					Value: types.VulnerabilityDetail{
						Title:       "MyBatis-Plus vulnerable to SQL injection via TenantPlugin",
						Description: "MyBatis-Plus below 3.5.3.1 is vulnerable to SQL injection via the tenant ID value. This may allow remote attackers to execute arbitrary SQL commands.",
						References: []string{
							"https://nvd.nist.gov/vuln/detail/CVE-2023-25330",
							"https://github.com/FCncdn/MybatisPlusTenantPluginSQLInjection-POC/blob/master/Readme.en.md",
							"https://github.com/baomidou/mybatis-plus",
						},
						Severity:     types.SeverityCritical,
						CvssVectorV3: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
						CvssScoreV3:  9.8,
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2023-25330",
					},
					Value: map[string]interface{}{},
				},
				{
					Key: []string{
						"data-source",
						"cargo::GitHub Security Advisory Rust",
					},
					Value: types.DataSource{
						ID:   vulnerability.GHSA,
						Name: "GitHub Security Advisory Rust",
						URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Arust",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2020-25792",
						"cargo::GitHub Security Advisory Rust",
						"sized-chunks",
					},
					Value: types.Advisory{
						VendorIDs: []string{
							"GHSA-mp6f-p9gp-vpj9",
						},
						PatchedVersions:    []string{"0.6.3"},
						VulnerableVersions: []string{"<0.6.3"},
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2020-25792",
						"ghsa",
					},
					Value: types.VulnerabilityDetail{
						Title:       "Array size is not checked in sized-chunks",
						Description: "An issue was discovered in the sized-chunks crate through 0.6.2 for Rust. In the Chunk implementation, the array size is not checked when constructed with pair().",
						References: []string{
							"https://nvd.nist.gov/vuln/detail/CVE-2020-25792",
							"https://github.com/bodil/sized-chunks/issues/11",
							"https://github.com/bodil/sized-chunks",
							"https://rustsec.org/advisories/RUSTSEC-2020-0041.html",
						},
						Severity:     types.SeverityHigh,
						CvssVectorV3: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
						CvssScoreV3:  7.5,
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2020-25792",
					},
					Value: map[string]interface{}{},
				},
				{
					Key: []string{
						"data-source",
						"go::GitHub Security Advisory Go",
					},
					Value: types.DataSource{
						ID:   vulnerability.GHSA,
						Name: "GitHub Security Advisory Go",
						URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Ago",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2020-8911",
						"go::GitHub Security Advisory Go",
						"github.com/aws/aws-sdk-go",
					},
					Value: types.Advisory{
						VendorIDs: []string{
							"GHSA-f5pg-7wfw-84q9",
						},
						PatchedVersions:    []string{"1.34.0"},
						VulnerableVersions: []string{"<1.34.0"},
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2020-8911",
						"ghsa",
					},
					Value: types.VulnerabilityDetail{
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
							"https://github.com/aws/aws-sdk-go",
							"https://github.com/sophieschmieg/exploits/tree/master/aws_s3_crypto_poc",
							"https://pkg.go.dev/vuln/GO-2022-0646",
						},
						Severity:     types.SeverityMedium,
						CvssVectorV3: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C",
						CvssScoreV3:  8.8,
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2020-8911",
					},
					Value: map[string]interface{}{},
				},
				{
					Key: []string{
						"data-source",
						"swift::GitHub Security Advisory Swift",
					},
					Value: types.DataSource{
						ID:   vulnerability.GHSA,
						Name: "GitHub Security Advisory Swift",
						URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Aswift",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2022-3215",
						"swift::GitHub Security Advisory Swift",
						"github.com/apple/swift-nio",
					},
					Value: types.Advisory{
						VendorIDs: []string{
							"GHSA-7fj7-39wj-c64f",
						},
						PatchedVersions: []string{
							"2.42.0",
							"2.39.1",
							"2.29.1",
						},
						VulnerableVersions: []string{
							">=2.41.0, <2.42.0",
							">=2.39.0, <2.39.1",
							"<2.29.1",
						},
					},
				},
				{
					Key: []string{
						"data-source",
						"cocoapods::GitHub Security Advisory Swift",
					},
					Value: types.DataSource{
						ID:   vulnerability.GHSA,
						Name: "GitHub Security Advisory Swift",
						URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Aswift",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2022-3215",
						"cocoapods::GitHub Security Advisory Swift",
						"SwiftNIO",
					},
					Value: types.Advisory{
						VendorIDs: []string{
							"GHSA-7fj7-39wj-c64f",
						},
						PatchedVersions: []string{
							"2.42.0",
							"2.39.1",
							"2.29.1",
						},
						VulnerableVersions: []string{
							">=2.41.0, <2.42.0",
							">=2.39.0, <2.39.1",
							"<2.29.1",
						},
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2022-3215",
						"cocoapods::GitHub Security Advisory Swift",
						"_NIODataStructures",
					},
					Value: types.Advisory{
						VendorIDs: []string{
							"GHSA-7fj7-39wj-c64f",
						},
						PatchedVersions: []string{
							"2.42.0",
							"2.39.1",
							"2.29.1",
						},
						VulnerableVersions: []string{
							">=2.41.0, <2.42.0",
							">=2.39.0, <2.39.1",
							"<2.29.1",
						},
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2022-3215",
						"ghsa",
					},
					Value: types.VulnerabilityDetail{
						Title:       "SwiftNIO vulnerable to Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting')",
						Description: "`NIOHTTP1` and projects using it for generating HTTP responses, including SwiftNIO, can be subject to a HTTP Response Injection attack. This occurs when a HTTP/1.1 server accepts user generated input from an incoming request and reflects it into a HTTP/1.1 response header in some form. A malicious user can add newlines to their input (usually in encoded form) and \"inject\" those newlines into the returned HTTP response.\n\nThis capability allows users to work around security headers and HTTP/1.1 framing headers by injecting entirely false responses or other new headers. The injected false responses may also be treated as the response to subsequent requests, which can lead to XSS, cache poisoning, and a number of other flaws.\n\nThis issue was resolved by adding a default channel handler that polices outbound headers. This channel handler is added by default to channel pipelines, but can be removed by users if they are doing this validation themselves.",
						References: []string{
							"https://github.com/apple/swift-nio/security/advisories/GHSA-7fj7-39wj-c64f",
							"https://nvd.nist.gov/vuln/detail/CVE-2022-3215",
							"https://github.com/apple/swift-nio/commit/a16e2f54a25b2af217044e5168997009a505930f",
							"https://github.com/apple/swift-nio",
						},
						Severity:     types.SeverityMedium,
						CvssVectorV3: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
						CvssScoreV3:  5.3,
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2022-3215",
					},
					Value: map[string]interface{}{},
				},
			},
			noBuckets: [][]string{
				// We shouldn't save Go runtime vulnerabilities
				{
					"advisory-detail",
					"CVE-2023-45288",
				},
				{
					"vulnerability-detail",
					"CVE-2023-45288",
				},
				{
					"vulnerability-id",
					"CVE-2023-45288",
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
			wantErr: "JSON decode error",
		},
		{
			name:    "sad path (cocoapods-specs doesn't exist)",
			dir:     "testdata",
			wantErr: "no such file or directory",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := ghsa.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
				NoBuckets:  tt.noBuckets,
			})
		})
	}
}
