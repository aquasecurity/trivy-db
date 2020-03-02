package ghsa

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

func TestVulnSrc_Update(t *testing.T) {
	type args struct {
		dir string
	}
	tests := []struct {
		name        string
		args        args
		batchUpdate []db.BatchUpdateExpectation
		wantErr     string
	}{
		{
			name: "happy path",
			args: args{
				dir: "testdata",
			},
			batchUpdate: []db.BatchUpdateExpectation{
				{
					Args: db.BatchUpdateArgs{
						FnAnything: true,
					},
				},
			},
		},
		{
			name: "cache dir doesnt exist",
			args: args{
				dir: "badpathdoesnotexist",
			},
			wantErr: "no such file or directory",
		},
		{
			name: "BatchUpdate returns an error",
			args: args{
				dir: "testdata",
			},
			batchUpdate: []db.BatchUpdateExpectation{
				{
					Args: db.BatchUpdateArgs{
						FnAnything: true,
					},
					Returns: db.BatchUpdateReturns{
						Err: errors.New("error"),
					},
				},
			},
			wantErr: "error in GHSA save",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDBConfig := new(db.MockOperation)
			mockDBConfig.ApplyBatchUpdateExpectations(tt.batchUpdate)

			vs := VulnSrc{
				dbc:       mockDBConfig,
				ecosystem: Pip,
			}
			err := vs.Update(tt.args.dir)
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
			} else {
				assert.NoError(t, err, tt.name)
			}
			mockDBConfig.AssertExpectations(t)
		})
	}
}

func TestVulnSrc_save(t *testing.T) {
	type args struct {
		ghsas []GithubSecurityAdvisory
	}
	tests := []struct {
		name                   string
		ecosystem              Ecosystem
		args                   args
		putAdvisory            []db.PutAdvisoryExpectation
		putVulnerabilityDetail []db.PutVulnerabilityDetailExpectation
		putSeverity            []db.PutSeverityExpectation
		wantErr                string
	}{
		{
			name:      "happy path composer",
			ecosystem: Composer,
			args: args{
				ghsas: []GithubSecurityAdvisory{
					{
						Severity:  "HIGH",
						UpdatedAt: "2019-12-17T19:42:32Z",
						Package: Package{
							Ecosystem: "COMPOSER",
							Name:      "contao/core-bundle",
						},
						Advisory: GhsaAdvisory{
							DatabaseId: 1848,
							Id:         "MDE2OlNlY3VyaXR5QWR2aXNvcnlHSFNBLXdqeDgtY2dybS1oaDhw",
							GhsaId:     "GHSA-wjx8-cgrm-hh8p",
							References: []Reference{
								{
									Url: "https://github.com/contao/contao/security/advisories/GHSA-wjx8-cgrm-hh8p",
								},
								{
									Url: "https://nvd.nist.gov/vuln/detail/CVE-2019-19745",
								},
							},
							Identifiers: []Identifier{
								{
									Type:  "GHSA",
									Value: "GHSA-wjx8-cgrm-hh8p",
								},
							},
							Description: "### Impact\n\nA back end user with access to the form generator can upload arbitrary files and execute them on the server.\n\n### Patches\n\nUpdate to Contao 4.4.46 or 4.8.6.\n\n### Workarounds\n\nConfigure your web server so it does not execute PHP files and other scripts in the Contao file upload directory.\n\n### References\n\nhttps://contao.org/en/security-advisories/unrestricted-file-uploads.html\n\n### For more information\n\nIf you have any questions or comments about this advisory, open an issue in [contao/contao](https://github.com/contao/contao/issues/new/choose).",
							Origin:      "UNSPECIFIED",
							PublishedAt: "2019-12-17T22:53:10Z",
							Severity:    "HIGH",
							Summary:     "High severity vulnerability that affects contao/core-bundle",
							UpdatedAt:   "2019-12-17T22:53:10Z",
							WithdrawnAt: "",
						},
						Versions: []Version{
							{
								FirstPatchedVersion: FirstPatchedVersion{
									Identifier: "4.8.6",
								},
								VulnerableVersionRange: "\u003e= 4.5.0, \u003c 4.8.6",
							},
							{
								FirstPatchedVersion: FirstPatchedVersion{
									Identifier: "4.4.46",
								},
								VulnerableVersionRange: "\u003e= 4.0.0, \u003c 4.4.46",
							},
							{
								FirstPatchedVersion: FirstPatchedVersion{
									Identifier: "< 5.8.6",
								},
								VulnerableVersionRange: "\u003e= 4.5.0, \u003c 4.8.6",
							},
						},
					},
				},
			},
			putAdvisory: []db.PutAdvisoryExpectation{
				{
					Args: db.PutAdvisoryArgs{
						TxAnything:      true,
						Source:          "GitHub Security Advisory Composer",
						PkgName:         "contao/core-bundle",
						VulnerabilityID: "GHSA-wjx8-cgrm-hh8p",
						Advisory: Advisory{
							PatchedVersions: []string{
								"4.8.6",
								"4.4.46",
								"5.8.6",
							},
							VulnerableVersions: []string{
								"\u003e= 4.5.0, \u003c 4.8.6",
								"\u003e= 4.0.0, \u003c 4.4.46",
								"\u003e= 4.5.0, \u003c 4.8.6, \u003c 5.8.6",
							},
						},
					},
				},
			},
			putVulnerabilityDetail: []db.PutVulnerabilityDetailExpectation{
				{
					Args: db.PutVulnerabilityDetailArgs{
						TxAnything:      true,
						Source:          vulnerability.GHSAComposer,
						VulnerabilityID: "GHSA-wjx8-cgrm-hh8p",
						Vulnerability: types.VulnerabilityDetail{
							ID:       "GHSA-wjx8-cgrm-hh8p",
							Severity: types.SeverityHigh,
							References: []string{
								"https://github.com/contao/contao/security/advisories/GHSA-wjx8-cgrm-hh8p",
								"https://nvd.nist.gov/vuln/detail/CVE-2019-19745",
							},
							Title:       "High severity vulnerability that affects contao/core-bundle",
							Description: "### Impact\n\nA back end user with access to the form generator can upload arbitrary files and execute them on the server.\n\n### Patches\n\nUpdate to Contao 4.4.46 or 4.8.6.\n\n### Workarounds\n\nConfigure your web server so it does not execute PHP files and other scripts in the Contao file upload directory.\n\n### References\n\nhttps://contao.org/en/security-advisories/unrestricted-file-uploads.html\n\n### For more information\n\nIf you have any questions or comments about this advisory, open an issue in [contao/contao](https://github.com/contao/contao/issues/new/choose).",
						},
					},
				},
			},
			putSeverity: []db.PutSeverityExpectation{
				{
					Args: db.PutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "GHSA-wjx8-cgrm-hh8p",
						Severity:        types.SeverityUnknown,
					},
				},
			},
		},
		{
			name:      "happy path maven",
			ecosystem: Maven,
			args: args{
				ghsas: []GithubSecurityAdvisory{
					{
						Severity:  "MODERATE",
						UpdatedAt: "2018-10-18T18:05:52Z",
						Package: Package{
							Ecosystem: "MAVEN",
							Name:      "org.springframework.boot:spring-boot",
						},
						Advisory: GhsaAdvisory{
							DatabaseId: 873,
							Id:         "MDE2OlNlY3VyaXR5QWR2aXNvcnlHSFNBLXh4NjUtY2M3Zy05cGZw",
							GhsaId:     "GHSA-xx65-cc7g-9pfp",
							References: []Reference{
								{
									Url: "https://nvd.nist.gov/vuln/detail/CVE-2018-1196",
								},
							},
							Identifiers: []Identifier{
								{
									Type:  "GHSA",
									Value: "GHSA-xx65-cc7g-9pfp",
								},
								{
									Type:  "CVE",
									Value: "CVE-2018-1196",
								},
							},
							Description: "Spring Boot supports an embedded launch script that can be used to easily run the application as a systemd or init.d linux service. The script included with Spring Boot 1.5.9 and earlier and 2.0.0.M1 through 2.0.0.M7 is susceptible to a symlink attack which allows the \"run_user\" to overwrite and take ownership of any file on the same system. In order to instigate the attack, the application must be installed as a service and the \"run_user\" requires shell access to the server. Spring Boot application that are not installed as a service, or are not using the embedded launch script are not susceptible.",
							Origin:      "UNSPECIFIED",
							PublishedAt: "2018-10-18T18:05:57Z",
							Severity:    "MODERATE",
							Summary:     "Moderate severity vulnerability that affects org.springframework.boot:spring-boot",
							UpdatedAt:   "2019-07-03T21:02:04Z",
							WithdrawnAt: "",
						},
						Versions: []Version{
							{
								FirstPatchedVersion: FirstPatchedVersion{
									Identifier: "1.5.10",
								},
								VulnerableVersionRange: "\u003e= 1.5.0, \u003c 1.5.10",
							},
						},
					},
				},
			},
			putAdvisory: []db.PutAdvisoryExpectation{
				{
					Args: db.PutAdvisoryArgs{
						TxAnything:      true,
						Source:          "GitHub Security Advisory Maven",
						PkgName:         "org.springframework.boot:spring-boot",
						VulnerabilityID: "CVE-2018-1196",
						Advisory: Advisory{
							PatchedVersions: []string{
								"1.5.10",
							},
							VulnerableVersions: []string{
								"\u003e= 1.5.0, \u003c 1.5.10",
							},
						},
					},
				},
			},
			putVulnerabilityDetail: []db.PutVulnerabilityDetailExpectation{
				{
					Args: db.PutVulnerabilityDetailArgs{
						TxAnything:      true,
						Source:          vulnerability.GHSAMaven,
						VulnerabilityID: "CVE-2018-1196",
						Vulnerability: types.VulnerabilityDetail{
							ID:          "CVE-2018-1196",
							Severity:    types.SeverityMedium,
							References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2018-1196"},
							Title:       "Moderate severity vulnerability that affects org.springframework.boot:spring-boot",
							Description: "Spring Boot supports an embedded launch script that can be used to easily run the application as a systemd or init.d linux service. The script included with Spring Boot 1.5.9 and earlier and 2.0.0.M1 through 2.0.0.M7 is susceptible to a symlink attack which allows the \"run_user\" to overwrite and take ownership of any file on the same system. In order to instigate the attack, the application must be installed as a service and the \"run_user\" requires shell access to the server. Spring Boot application that are not installed as a service, or are not using the embedded launch script are not susceptible.",
						},
					},
				},
			},
			putSeverity: []db.PutSeverityExpectation{
				{
					Args: db.PutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2018-1196",
						Severity:        types.SeverityUnknown,
					},
				},
			},
		},
		{
			name:      "happy path npm",
			ecosystem: Npm,
			args: args{
				ghsas: []GithubSecurityAdvisory{
					{
						Severity:  "MODERATE",
						UpdatedAt: "2018-10-09T00:23:02Z",
						Package: Package{
							Ecosystem: "NPM",
							Name:      "atob",
						},
						Advisory: GhsaAdvisory{
							DatabaseId: 670,
							Id:         "MDE2OlNlY3VyaXR5QWR2aXNvcnlHSFNBLTh3NGgtM2NtMy0ycG0y",
							GhsaId:     "GHSA-8w4h-3cm3-2pm2",
							References: []Reference{
								{
									Url: "https://nvd.nist.gov/vuln/detail/CVE-2018-3745",
								},
							},
							Identifiers: []Identifier{
								{
									Type:  "GHSA",
									Value: "GHSA-8w4h-3cm3-2pm2",
								},
								{
									Type:  "CVE",
									Value: "CVE-2018-3745",
								},
							},
							Description: "atob 2.0.3 and earlier allocates uninitialized Buffers when number is passed in input on Node.js 4.x and below.",
							Origin:      "UNSPECIFIED",
							PublishedAt: "2018-10-09T00:56:26Z",
							Severity:    "MODERATE",
							Summary:     "Moderate severity vulnerability that affects atob",
							UpdatedAt:   "2019-07-03T21:02:03Z",
							WithdrawnAt: "",
						},
						Versions: []Version{
							{
								FirstPatchedVersion: FirstPatchedVersion{
									Identifier: "2.1.0",
								},
								VulnerableVersionRange: "\u003c 2.1.0",
							},
						},
					},
				},
			},
			putAdvisory: []db.PutAdvisoryExpectation{
				{
					Args: db.PutAdvisoryArgs{
						TxAnything:      true,
						Source:          "GitHub Security Advisory Npm",
						PkgName:         "atob",
						VulnerabilityID: "CVE-2018-3745",
						Advisory: Advisory{
							PatchedVersions:    []string{"2.1.0"},
							VulnerableVersions: []string{"\u003c 2.1.0"},
						},
					},
				},
			},
			putVulnerabilityDetail: []db.PutVulnerabilityDetailExpectation{
				{
					Args: db.PutVulnerabilityDetailArgs{
						TxAnything:      true,
						Source:          vulnerability.GHSANpm,
						VulnerabilityID: "CVE-2018-3745",
						Vulnerability: types.VulnerabilityDetail{
							ID:          "CVE-2018-3745",
							Severity:    types.SeverityMedium,
							References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2018-3745"},
							Title:       "Moderate severity vulnerability that affects atob",
							Description: "atob 2.0.3 and earlier allocates uninitialized Buffers when number is passed in input on Node.js 4.x and below.",
						},
					},
				},
			},
			putSeverity: []db.PutSeverityExpectation{
				{
					Args: db.PutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2018-3745",
						Severity:        types.SeverityUnknown,
					},
				},
			},
		},
		{
			name:      "happy path nuget",
			ecosystem: Nuget,
			args: args{
				ghsas: []GithubSecurityAdvisory{
					{
						Severity:  "MODERATE",
						UpdatedAt: "2019-07-25T15:56:11Z",
						Package: Package{
							Ecosystem: "NUGET",
							Name:      "CLEditor",
						},
						Advisory: GhsaAdvisory{
							DatabaseId: 1600,
							Id:         "MDE2OlNlY3VyaXR5QWR2aXNvcnlHSFNBLWhoNTYteDYyZy1ndmhj",
							GhsaId:     "GHSA-hh56-x62g-gvhc",
							References: []Reference{
								{
									Url: "https://nvd.nist.gov/vuln/detail/CVE-2019-1010113",
								},
							},
							Identifiers: []Identifier{
								{
									Type:  "GHSA",
									Value: "GHSA-hh56-x62g-gvhc",
								},
								{
									Type:  "CVE",
									Value: "CVE-2019-1010113",
								},
							},
							Description: "Premium Software CLEditor 1.4.5 and earlier is affected by: Cross Site Scripting (XSS). The impact is: An attacker might be able to inject arbitrary html and script code into the web site. The component is: jQuery plug-in. The attack vector is: the victim must open a crafted href attribute of a link (A) element.",
							Origin:      "UNSPECIFIED",
							PublishedAt: "2019-07-26T16:10:06Z",
							Severity:    "MODERATE",
							Summary:     "Moderate severity vulnerability that affects CLEditor",
							UpdatedAt:   "2019-10-24T01:33:56Z",
							WithdrawnAt: "",
						},
						Versions: []Version{
							{
								FirstPatchedVersion: FirstPatchedVersion{
									Identifier: "",
								},
								VulnerableVersionRange: "\u003c= 1.4.5",
							},
						},
					},
				},
			},
			putAdvisory: []db.PutAdvisoryExpectation{
				{
					Args: db.PutAdvisoryArgs{
						TxAnything:      true,
						Source:          "GitHub Security Advisory Nuget",
						PkgName:         "CLEditor",
						VulnerabilityID: "CVE-2019-1010113",
						Advisory: Advisory{
							PatchedVersions:    []string{""},
							VulnerableVersions: []string{"\u003c= 1.4.5"},
						},
					},
				},
			},
			putVulnerabilityDetail: []db.PutVulnerabilityDetailExpectation{
				{
					Args: db.PutVulnerabilityDetailArgs{
						TxAnything:      true,
						Source:          vulnerability.GHSANuget,
						VulnerabilityID: "CVE-2019-1010113",
						Vulnerability: types.VulnerabilityDetail{
							ID:          "CVE-2019-1010113",
							Severity:    types.SeverityMedium,
							References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2019-1010113"},
							Title:       "Moderate severity vulnerability that affects CLEditor",
							Description: "Premium Software CLEditor 1.4.5 and earlier is affected by: Cross Site Scripting (XSS). The impact is: An attacker might be able to inject arbitrary html and script code into the web site. The component is: jQuery plug-in. The attack vector is: the victim must open a crafted href attribute of a link (A) element.",
						},
					},
				},
			},
			putSeverity: []db.PutSeverityExpectation{
				{
					Args: db.PutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2019-1010113",
						Severity:        types.SeverityUnknown,
					},
				},
			},
		},
		{
			name:      "happy path pip",
			ecosystem: Pip,
			args: args{
				ghsas: []GithubSecurityAdvisory{
					{
						Severity:  "MODERATE",
						UpdatedAt: "2018-10-04T18:05:59Z",
						Package: Package{
							Ecosystem: "PIP",
							Name:      "django",
						},
						Advisory: GhsaAdvisory{
							DatabaseId: 663,
							Id:         "MDE2OlNlY3VyaXR5QWR2aXNvcnlHSFNBLTVoZzMtNmMyZi1mM3dy",
							GhsaId:     "GHSA-5hg3-6c2f-f3wr",
							References: []Reference{
								{
									Url: "https://nvd.nist.gov/vuln/detail/CVE-2018-14574",
								},
							},
							Identifiers: []Identifier{
								{
									Type:  "GHSA",
									Value: "GHSA-5hg3-6c2f-f3wr",
								},
								{
									Type:  "CVE",
									Value: "CVE-2018-14574",
								},
							},
							Description: "django.middleware.common.CommonMiddleware in Django 1.11.x before 1.11.15 and 2.0.x before 2.0.8 has an Open Redirect.",
							Origin:      "UNSPECIFIED",
							PublishedAt: "2018-10-04T21:58:46Z",
							Severity:    "MODERATE",
							Summary:     "Moderate severity vulnerability that affects django",
							UpdatedAt:   "2019-07-03T21:02:03Z",
							WithdrawnAt: "",
						},
						Versions: []Version{
							{
								FirstPatchedVersion: FirstPatchedVersion{
									Identifier: "2.0.8",
								},
								VulnerableVersionRange: "\u003e= 2.0, \u003c 2.0.8",
							},
							{
								FirstPatchedVersion: FirstPatchedVersion{
									Identifier: "1.11.15",
								},
								VulnerableVersionRange: "\u003e= 1.11.0, \u003c 1.11.15",
							},
						},
					},
				},
			},
			putAdvisory: []db.PutAdvisoryExpectation{
				{
					Args: db.PutAdvisoryArgs{
						TxAnything:      true,
						Source:          "GitHub Security Advisory Pip",
						PkgName:         "django",
						VulnerabilityID: "CVE-2018-14574",
						Advisory: Advisory{
							PatchedVersions: []string{
								"2.0.8",
								"1.11.15",
							},
							VulnerableVersions: []string{
								"\u003e= 2.0, \u003c 2.0.8",
								"\u003e= 1.11.0, \u003c 1.11.15",
							},
						},
					},
				},
			},
			putVulnerabilityDetail: []db.PutVulnerabilityDetailExpectation{
				{
					Args: db.PutVulnerabilityDetailArgs{
						TxAnything:      true,
						Source:          vulnerability.GHSAPip,
						VulnerabilityID: "CVE-2018-14574",
						Vulnerability: types.VulnerabilityDetail{
							ID:       "CVE-2018-14574",
							Severity: types.SeverityMedium,
							References: []string{
								"https://nvd.nist.gov/vuln/detail/CVE-2018-14574",
							},
							Title:       "Moderate severity vulnerability that affects django",
							Description: "django.middleware.common.CommonMiddleware in Django 1.11.x before 1.11.15 and 2.0.x before 2.0.8 has an Open Redirect.",
						},
					},
				},
			},
			putSeverity: []db.PutSeverityExpectation{
				{
					Args: db.PutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2018-14574",
						Severity:        types.SeverityUnknown,
					},
				},
			},
		},
		{
			name:      "happy path rubygems",
			ecosystem: Rubygems,
			args: args{
				ghsas: []GithubSecurityAdvisory{
					{
						Severity:  "HIGH",
						UpdatedAt: "2018-12-05T17:16:50Z",
						Package: Package{
							Ecosystem: "RUBYGEMS",
							Name:      "activestorage",
						},
						Advisory: GhsaAdvisory{
							DatabaseId: 1010,
							Id:         "MDE2OlNlY3VyaXR5QWR2aXNvcnlHSFNBLTdycjctcmNqdy01NnZq",
							GhsaId:     "GHSA-7rr7-rcjw-56vj",
							References: []Reference{
								{
									Url: "https://nvd.nist.gov/vuln/detail/CVE-2018-16477",
								},
							},
							Identifiers: []Identifier{
								{
									Type:  "GHSA",
									Value: "GHSA-7rr7-rcjw-56vj",
								},
								{
									Type:  "CVE",
									Value: "CVE-2018-16477",
								},
							},
							Description: "A bypass vulnerability in Active Storage \u003e= 5.2.0 for Google Cloud Storage and Disk services allow an attacker to modify the `content-disposition` and `content-type` parameters which can be used in with HTML files and have them executed inline. Additionally, if combined with other techniques such as cookie bombing and specially crafted AppCache manifests, an attacker can gain access to private signed URLs within a specific storage path.",
							Origin:      "UNSPECIFIED",
							PublishedAt: "2018-12-05T17:17:02Z",
							Severity:    "HIGH",
							Summary:     "High severity vulnerability that affects activestorage",
							UpdatedAt:   "2019-07-03T21:02:05Z",
							WithdrawnAt: "",
						},
						Versions: []Version{
							{
								FirstPatchedVersion: FirstPatchedVersion{
									Identifier: "5.2.1.1",
								},
								VulnerableVersionRange: "\u003e= 5.2.0, \u003c 5.2.1.1",
							},
						},
					},
				},
			},
			putAdvisory: []db.PutAdvisoryExpectation{
				{
					Args: db.PutAdvisoryArgs{
						TxAnything:      true,
						Source:          "GitHub Security Advisory Rubygems",
						PkgName:         "activestorage",
						VulnerabilityID: "CVE-2018-16477",
						Advisory: Advisory{
							PatchedVersions:    []string{"5.2.1.1"},
							VulnerableVersions: []string{"\u003e= 5.2.0, \u003c 5.2.1.1"},
						},
					},
				},
			},
			putVulnerabilityDetail: []db.PutVulnerabilityDetailExpectation{
				{
					Args: db.PutVulnerabilityDetailArgs{
						TxAnything:      true,
						Source:          vulnerability.GHSARubygems,
						VulnerabilityID: "CVE-2018-16477",
						Vulnerability: types.VulnerabilityDetail{
							ID:          "CVE-2018-16477",
							Severity:    types.SeverityHigh,
							References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2018-16477"},
							Title:       "High severity vulnerability that affects activestorage",
							Description: "A bypass vulnerability in Active Storage \u003e= 5.2.0 for Google Cloud Storage and Disk services allow an attacker to modify the `content-disposition` and `content-type` parameters which can be used in with HTML files and have them executed inline. Additionally, if combined with other techniques such as cookie bombing and specially crafted AppCache manifests, an attacker can gain access to private signed URLs within a specific storage path.",
						},
					},
				},
			},
			putSeverity: []db.PutSeverityExpectation{
				{
					Args: db.PutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2018-16477",
						Severity:        types.SeverityUnknown,
					},
				},
			},
		},
		{
			name:      "putAdvisory returns an error",
			ecosystem: Rubygems,
			args: args{
				ghsas: []GithubSecurityAdvisory{
					{
						Severity:  "HIGH",
						UpdatedAt: "2018-12-05T17:16:50Z",
						Package: Package{
							Ecosystem: "RUBYGEMS",
							Name:      "activestorage",
						},
						Advisory: GhsaAdvisory{
							DatabaseId: 1010,
							Id:         "MDE2OlNlY3VyaXR5QWR2aXNvcnlHSFNBLTdycjctcmNqdy01NnZq",
							GhsaId:     "GHSA-7rr7-rcjw-56vj",
							References: []Reference{
								{
									Url: "https://nvd.nist.gov/vuln/detail/CVE-2018-16477",
								},
							},
							Identifiers: []Identifier{
								{
									Type:  "GHSA",
									Value: "GHSA-7rr7-rcjw-56vj",
								},
								{
									Type:  "CVE",
									Value: "CVE-2018-16477",
								},
							},
							Description: "A bypass vulnerability in Active Storage \u003e= 5.2.0 for Google Cloud Storage and Disk services allow an attacker to modify the `content-disposition` and `content-type` parameters which can be used in with HTML files and have them executed inline. Additionally, if combined with other techniques such as cookie bombing and specially crafted AppCache manifests, an attacker can gain access to private signed URLs within a specific storage path.",
							Origin:      "UNSPECIFIED",
							PublishedAt: "2018-12-05T17:17:02Z",
							Severity:    "HIGH",
							Summary:     "High severity vulnerability that affects activestorage",
							UpdatedAt:   "2019-07-03T21:02:05Z",
							WithdrawnAt: "",
						},
						Versions: []Version{
							{
								FirstPatchedVersion: FirstPatchedVersion{
									Identifier: "5.2.1.1",
								},
								VulnerableVersionRange: "\u003e= 5.2.0, \u003c 5.2.1.1",
							},
						},
					},
				},
			},
			putAdvisory: []db.PutAdvisoryExpectation{
				{
					Args: db.PutAdvisoryArgs{
						TxAnything:      true,
						Source:          "GitHub Security Advisory Rubygems",
						PkgName:         "activestorage",
						VulnerabilityID: "CVE-2018-16477",
						Advisory: Advisory{
							PatchedVersions:    []string{"5.2.1.1"},
							VulnerableVersions: []string{"\u003e= 5.2.0, \u003c 5.2.1.1"},
						},
					},
					Returns: db.PutAdvisoryReturns{
						Err: errors.New("error"),
					},
				},
			},
			wantErr: "failed to save GHSA",
		},
		{
			name:      "PutVulnerabilityDetail returns an error",
			ecosystem: Rubygems,
			args: args{
				ghsas: []GithubSecurityAdvisory{
					{
						Severity:  "HIGH",
						UpdatedAt: "2018-12-05T17:16:50Z",
						Package: Package{
							Ecosystem: "RUBYGEMS",
							Name:      "activestorage",
						},
						Advisory: GhsaAdvisory{
							DatabaseId: 1010,
							Id:         "MDE2OlNlY3VyaXR5QWR2aXNvcnlHSFNBLTdycjctcmNqdy01NnZq",
							GhsaId:     "GHSA-7rr7-rcjw-56vj",
							References: []Reference{
								{
									Url: "https://nvd.nist.gov/vuln/detail/CVE-2018-16477",
								},
							},
							Identifiers: []Identifier{
								{
									Type:  "GHSA",
									Value: "GHSA-7rr7-rcjw-56vj",
								},
								{
									Type:  "CVE",
									Value: "CVE-2018-16477",
								},
							},
							Description: "A bypass vulnerability in Active Storage \u003e= 5.2.0 for Google Cloud Storage and Disk services allow an attacker to modify the `content-disposition` and `content-type` parameters which can be used in with HTML files and have them executed inline. Additionally, if combined with other techniques such as cookie bombing and specially crafted AppCache manifests, an attacker can gain access to private signed URLs within a specific storage path.",
							Origin:      "UNSPECIFIED",
							PublishedAt: "2018-12-05T17:17:02Z",
							Severity:    "HIGH",
							Summary:     "High severity vulnerability that affects activestorage",
							UpdatedAt:   "2019-07-03T21:02:05Z",
							WithdrawnAt: "",
						},
						Versions: []Version{
							{
								FirstPatchedVersion: FirstPatchedVersion{
									Identifier: "5.2.1.1",
								},
								VulnerableVersionRange: "\u003e= 5.2.0, \u003c 5.2.1.1",
							},
						},
					},
				},
			},
			putAdvisory: []db.PutAdvisoryExpectation{
				{
					Args: db.PutAdvisoryArgs{
						TxAnything:      true,
						Source:          "GitHub Security Advisory Rubygems",
						PkgName:         "activestorage",
						VulnerabilityID: "CVE-2018-16477",
						Advisory: Advisory{
							PatchedVersions:    []string{"5.2.1.1"},
							VulnerableVersions: []string{"\u003e= 5.2.0, \u003c 5.2.1.1"},
						},
					},
				},
			},
			putVulnerabilityDetail: []db.PutVulnerabilityDetailExpectation{
				{
					Args: db.PutVulnerabilityDetailArgs{
						TxAnything:      true,
						Source:          vulnerability.GHSARubygems,
						VulnerabilityID: "CVE-2018-16477",
						Vulnerability: types.VulnerabilityDetail{
							ID:          "CVE-2018-16477",
							Severity:    types.SeverityHigh,
							References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2018-16477"},
							Title:       "High severity vulnerability that affects activestorage",
							Description: "A bypass vulnerability in Active Storage \u003e= 5.2.0 for Google Cloud Storage and Disk services allow an attacker to modify the `content-disposition` and `content-type` parameters which can be used in with HTML files and have them executed inline. Additionally, if combined with other techniques such as cookie bombing and specially crafted AppCache manifests, an attacker can gain access to private signed URLs within a specific storage path.",
						},
					},
					Returns: db.PutVulnerabilityDetailReturns{
						Err: errors.New("error"),
					},
				},
			},
			wantErr: "failed to save GHSA vulnerability detail",
		},
		{
			name:      "PutVulnerabilitySeveiry returns an error",
			ecosystem: Rubygems,
			args: args{
				ghsas: []GithubSecurityAdvisory{
					{
						Severity:  "HIGH",
						UpdatedAt: "2018-12-05T17:16:50Z",
						Package: Package{
							Ecosystem: "RUBYGEMS",
							Name:      "activestorage",
						},
						Advisory: GhsaAdvisory{
							DatabaseId: 1010,
							Id:         "MDE2OlNlY3VyaXR5QWR2aXNvcnlHSFNBLTdycjctcmNqdy01NnZq",
							GhsaId:     "GHSA-7rr7-rcjw-56vj",
							References: []Reference{
								{
									Url: "https://nvd.nist.gov/vuln/detail/CVE-2018-16477",
								},
							},
							Identifiers: []Identifier{
								{
									Type:  "GHSA",
									Value: "GHSA-7rr7-rcjw-56vj",
								},
								{
									Type:  "CVE",
									Value: "CVE-2018-16477",
								},
							},
							Description: "A bypass vulnerability in Active Storage \u003e= 5.2.0 for Google Cloud Storage and Disk services allow an attacker to modify the `content-disposition` and `content-type` parameters which can be used in with HTML files and have them executed inline. Additionally, if combined with other techniques such as cookie bombing and specially crafted AppCache manifests, an attacker can gain access to private signed URLs within a specific storage path.",
							Origin:      "UNSPECIFIED",
							PublishedAt: "2018-12-05T17:17:02Z",
							Severity:    "HIGH",
							Summary:     "High severity vulnerability that affects activestorage",
							UpdatedAt:   "2019-07-03T21:02:05Z",
							WithdrawnAt: "",
						},
						Versions: []Version{
							{
								FirstPatchedVersion: FirstPatchedVersion{
									Identifier: "5.2.1.1",
								},
								VulnerableVersionRange: "\u003e= 5.2.0, \u003c 5.2.1.1",
							},
						},
					},
				},
			},
			putAdvisory: []db.PutAdvisoryExpectation{
				{
					Args: db.PutAdvisoryArgs{
						TxAnything:      true,
						Source:          "GitHub Security Advisory Rubygems",
						PkgName:         "activestorage",
						VulnerabilityID: "CVE-2018-16477",
						Advisory: Advisory{
							PatchedVersions:    []string{"5.2.1.1"},
							VulnerableVersions: []string{"\u003e= 5.2.0, \u003c 5.2.1.1"},
						},
					},
				},
			},
			putVulnerabilityDetail: []db.PutVulnerabilityDetailExpectation{
				{
					Args: db.PutVulnerabilityDetailArgs{
						TxAnything:      true,
						Source:          vulnerability.GHSARubygems,
						VulnerabilityID: "CVE-2018-16477",
						Vulnerability: types.VulnerabilityDetail{
							ID:          "CVE-2018-16477",
							Severity:    types.SeverityHigh,
							References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2018-16477"},
							Title:       "High severity vulnerability that affects activestorage",
							Description: "A bypass vulnerability in Active Storage \u003e= 5.2.0 for Google Cloud Storage and Disk services allow an attacker to modify the `content-disposition` and `content-type` parameters which can be used in with HTML files and have them executed inline. Additionally, if combined with other techniques such as cookie bombing and specially crafted AppCache manifests, an attacker can gain access to private signed URLs within a specific storage path.",
						},
					},
				},
			},
			putSeverity: []db.PutSeverityExpectation{
				{
					Args: db.PutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2018-16477",
						Severity:        types.SeverityUnknown,
					},
					Returns: db.PutSeverityReturns{
						Err: errors.New("error"),
					},
				},
			},
			wantErr: "failed to save GHSA vulnerability severity",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDBConfig := new(db.MockOperation)
			mockDBConfig.ApplyPutAdvisoryExpectations(tt.putAdvisory)
			mockDBConfig.ApplyPutVulnerabilityDetailExpectations(tt.putVulnerabilityDetail)
			mockDBConfig.ApplyPutSeverityExpectations(tt.putSeverity)

			vs := VulnSrc{
				dbc:       mockDBConfig,
				ecosystem: tt.ecosystem,
			}
			err := vs.commit(nil, tt.args.ghsas)

			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
			} else {
				assert.NoError(t, err, tt.name)
			}
			mockDBConfig.AssertExpectations(t)
		})
	}
}

func TestVulnSrc_Get(t *testing.T) {
	type args struct {
		release string
		pkgName string
	}
	tests := []struct {
		name                       string
		args                       args
		ecosystem                  Ecosystem
		forEachAdvisoryExpectation db.ForEachAdvisoryExpectation
		want                       []Advisory
		wantErr                    string
	}{
		{
			name:      "happy path composer",
			ecosystem: Composer,
			args: args{
				release: "GitHub Security Advisory Composer",
				pkgName: "contao/core-bundle",
			},
			forEachAdvisoryExpectation: db.ForEachAdvisoryExpectation{
				Args: db.ForEachAdvisoryArgs{
					Source:  "GitHub Security Advisory Composer",
					PkgName: "contao/core-bundle",
				},
				Returns: db.ForEachAdvisoryReturns{
					Value: map[string][]byte{
						"CVE-2019-19745": []byte(`{"VulnerableVersions": ["4.8.6", "4.4.46"], "PatchedVersions": ["\u003e= 4.5.0, \u003c 4.8.6", "\u003e= 4.0.0, \u003c 4.4.46"]}`),
					},
				},
			},
			want: []Advisory{
				{
					VulnerabilityID:    "CVE-2019-19745",
					VulnerableVersions: []string{"4.8.6", "4.4.46"},
					PatchedVersions:    []string{"\u003e= 4.5.0, \u003c 4.8.6", "\u003e= 4.0.0, \u003c 4.4.46"},
				},
			},
		},
		{
			name:      "happy path maven",
			ecosystem: Maven,
			args: args{
				release: "GitHub Security Advisory Maven",
				pkgName: "org.springframework.boot:spring-boot",
			},
			forEachAdvisoryExpectation: db.ForEachAdvisoryExpectation{
				Args: db.ForEachAdvisoryArgs{
					Source:  "GitHub Security Advisory Maven",
					PkgName: "org.springframework.boot:spring-boot",
				},
				Returns: db.ForEachAdvisoryReturns{
					Value: map[string][]byte{
						"CVE-2018-1196": []byte(`{"VulnerableVersions": ["1.5.10"], "PatchedVersions": ["\u003e= 1.5.0, \u003c 1.5.10"]}`),
					},
				},
			},
			want: []Advisory{
				{
					VulnerabilityID:    "CVE-2018-1196",
					VulnerableVersions: []string{"1.5.10"},
					PatchedVersions:    []string{"\u003e= 1.5.0, \u003c 1.5.10"},
				},
			},
		},
		{
			name:      "happy path npm",
			ecosystem: Npm,
			args: args{
				release: "GitHub Security Advisory Npm",
				pkgName: "atob",
			},
			forEachAdvisoryExpectation: db.ForEachAdvisoryExpectation{
				Args: db.ForEachAdvisoryArgs{
					Source:  "GitHub Security Advisory Npm",
					PkgName: "atob",
				},
				Returns: db.ForEachAdvisoryReturns{
					Value: map[string][]byte{
						"GHSA-8w4h-3cm3-2pm2": []byte(`{"VulnerableVersions": ["2.1.0"], "PatchedVersions": ["\u003c 2.1.0"]}`),
					},
				},
			},
			want: []Advisory{
				{
					VulnerabilityID:    "GHSA-8w4h-3cm3-2pm2",
					VulnerableVersions: []string{"2.1.0"},
					PatchedVersions:    []string{"\u003c 2.1.0"},
				},
			},
		},
		{
			name:      "happy path nuget",
			ecosystem: Nuget,
			args: args{
				release: "GitHub Security Advisory Nuget",
				pkgName: "CLEditor",
			},
			forEachAdvisoryExpectation: db.ForEachAdvisoryExpectation{
				Args: db.ForEachAdvisoryArgs{
					Source:  "GitHub Security Advisory Nuget",
					PkgName: "CLEditor",
				},
				Returns: db.ForEachAdvisoryReturns{
					Value: map[string][]byte{
						"GHSA-hh56-x62g-gvhc": []byte(`{"VulnerableVersions": [""], "PatchedVersions": ["\u003c= 1.4.5"]}`),
					},
				},
			},
			want: []Advisory{
				{
					VulnerabilityID:    "GHSA-hh56-x62g-gvhc",
					VulnerableVersions: []string{""},
					PatchedVersions:    []string{"\u003c= 1.4.5"},
				},
			},
		},
		{
			name:      "happy path pip",
			ecosystem: Pip,
			args: args{
				release: "GitHub Security Advisory Pip",
				pkgName: "django",
			},
			forEachAdvisoryExpectation: db.ForEachAdvisoryExpectation{
				Args: db.ForEachAdvisoryArgs{
					Source:  "GitHub Security Advisory Pip",
					PkgName: "django",
				},
				Returns: db.ForEachAdvisoryReturns{
					Value: map[string][]byte{
						"GHSA-5hg3-6c2f-f3wr": []byte(`{"VulnerableVersions": ["2.0.8", "1.11.15"], "PatchedVersions": ["\u003e= 2.0, \u003c 2.0.8", "\u003e= 1.11.0, \u003c 1.11.15"]}`),
					},
				},
			},
			want: []Advisory{
				{
					VulnerabilityID:    "GHSA-5hg3-6c2f-f3wr",
					VulnerableVersions: []string{"2.0.8", "1.11.15"},
					PatchedVersions:    []string{"\u003e= 2.0, \u003c 2.0.8", "\u003e= 1.11.0, \u003c 1.11.15"},
				},
			},
		},
		{
			name:      "happy path rubygems",
			ecosystem: Rubygems,
			args: args{
				release: "GitHub Security Advisory Rubygems",
				pkgName: "activestorage",
			},
			forEachAdvisoryExpectation: db.ForEachAdvisoryExpectation{
				Args: db.ForEachAdvisoryArgs{
					Source:  "GitHub Security Advisory Rubygems",
					PkgName: "activestorage",
				},
				Returns: db.ForEachAdvisoryReturns{
					Value: map[string][]byte{
						"GHSA-7rr7-rcjw-56vj": []byte(`{"VulnerableVersions": ["5.2.1.1"], "PatchedVersions": ["\u003e= 5.2.0, \u003c 5.2.1.1"]}`),
					},
				},
			},
			want: []Advisory{
				{
					VulnerabilityID:    "GHSA-7rr7-rcjw-56vj",
					VulnerableVersions: []string{"5.2.1.1"},
					PatchedVersions:    []string{"\u003e= 5.2.0, \u003c 5.2.1.1"},
				},
			},
		},
		{
			name:      "GetAdvisories returns an error",
			ecosystem: Composer,
			args: args{
				release: "contao/core-bundle",
				pkgName: "4.8.6",
			},
			forEachAdvisoryExpectation: db.ForEachAdvisoryExpectation{
				Args: db.ForEachAdvisoryArgs{
					Source:  "GitHub Security Advisory Composer",
					PkgName: "4.8.6",
				},
				Returns: db.ForEachAdvisoryReturns{
					Err: errors.New("error"),
				},
			},
			wantErr: "failed to iterate GHSA",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDBConfig := new(db.MockOperation)
			mockDBConfig.ApplyForEachAdvisoryExpectation(tt.forEachAdvisoryExpectation)

			vs := VulnSrc{
				dbc:       mockDBConfig,
				ecosystem: tt.ecosystem,
			}
			got, err := vs.Get(tt.args.pkgName)
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
			} else {
				assert.NoError(t, err, tt.name)
			}
			assert.Equal(t, tt.want, got, tt.name)
		})
	}
}
