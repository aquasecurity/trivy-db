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
		batchUpdate []db.OperationBatchUpdateExpectation
		wantErr     string
	}{
		{
			name: "happy path",
			args: args{
				dir: "testdata",
			},
			batchUpdate: []db.OperationBatchUpdateExpectation{
				{
					Args: db.OperationBatchUpdateArgs{
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
			batchUpdate: []db.OperationBatchUpdateExpectation{
				{
					Args: db.OperationBatchUpdateArgs{
						FnAnything: true,
					},
					Returns: db.OperationBatchUpdateReturns{
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
		putAdvisoryDetail      []db.OperationPutAdvisoryDetailExpectation
		putVulnerabilityDetail []db.OperationPutVulnerabilityDetailExpectation
		putDataSource          []db.OperationPutDataSourceExpectation
		putVulnerabilityID     []db.OperationPutVulnerabilityIDExpectation
		wantErr                string
	}{
		{
			name:      "ignore withdrawn advisory",
			ecosystem: Composer,
			args: args{
				ghsas: []GithubSecurityAdvisory{
					{
						Severity:  "MODERATE",
						UpdatedAt: "2021-02-10T18:26:25Z",
						Package: Package{
							Ecosystem: "COMPOSER",
							Name:      "adminer",
						},
						Advisory: GhsaAdvisory{
							DatabaseId: 3338,
							Id:         "MDE2OlNlY3VyaXR5QWR2aXNvcnlHSFNBLW01NmctM2c4di0ycnh3",
							GhsaId:     "GHSA-m56g-3g8v-2rxw",
							References: []Reference{
								{
									Url: "https://nvd.nist.gov/vuln/detail/CVE-2020-35572",
								},
								{
									Url: "https://github.com/advisories/GHSA-m56g-3g8v-2rxw",
								},
							},
							Identifiers: []Identifier{
								{
									Type:  "GHSA",
									Value: "GHSA-m56g-3g8v-2rxw",
								},
								{
									Type:  "CVE",
									Value: "CVE-2020-35572",
								},
							},
							Description: "**Withdrawn:** Duplicate of GHSA-9pgx-gcph-mpqr.\n\nAdminer before 4.7.9 allows XSS via the history parameter to the default URI. ",
							Origin:      "UNSPECIFIED",
							PublishedAt: "2021-02-11T20:46:53Z",
							Severity:    "MODERATE",
							Summary:     "XSS in Adminer",
							UpdatedAt:   "2021-02-11T20:46:56Z",
							WithdrawnAt: "2021-02-11T20:46:56Z",
						},
						Versions: []Version{
							{
								FirstPatchedVersion: FirstPatchedVersion{
									Identifier: "4.7.9",
								},
								VulnerableVersionRange: "\u003c 4.7.9",
							},
						},
					},
				},
			},
			putAdvisoryDetail:      []db.OperationPutAdvisoryDetailExpectation{},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{},
			putDataSource: []db.OperationPutDataSourceExpectation{
				{
					Args: db.OperationPutDataSourceArgs{
						TxAnything: true,
						BktName:    "GitHub Security Advisory Composer",
						Source: types.DataSource{
							Name: "GitHub Advisory Database Composer",
							URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Acomposer",
						},
					},
					Returns: db.OperationPutDataSourceReturns{},
				},
			},
			putVulnerabilityID: []db.OperationPutVulnerabilityIDExpectation{},
		},
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
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "GitHub Security Advisory Composer",
						PkgName:         "contao/core-bundle",
						VulnerabilityID: "GHSA-wjx8-cgrm-hh8p",
						Advisory: types.Advisory{
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
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
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
			putDataSource: []db.OperationPutDataSourceExpectation{
				{
					Args: db.OperationPutDataSourceArgs{
						TxAnything: true,
						BktName:    "GitHub Security Advisory Composer",
						Source: types.DataSource{
							Name: "GitHub Advisory Database Composer",
							URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Acomposer",
						},
					},
					Returns: db.OperationPutDataSourceReturns{},
				},
			},
			putVulnerabilityID: []db.OperationPutVulnerabilityIDExpectation{
				{
					Args: db.OperationPutVulnerabilityIDArgs{
						TxAnything:      true,
						VulnerabilityID: "GHSA-wjx8-cgrm-hh8p",
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
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "GitHub Security Advisory Maven",
						PkgName:         "org.springframework.boot:spring-boot",
						VulnerabilityID: "CVE-2018-1196",
						Advisory: types.Advisory{
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
			putDataSource: []db.OperationPutDataSourceExpectation{
				{
					Args: db.OperationPutDataSourceArgs{
						TxAnything: true,
						BktName:    "GitHub Security Advisory Maven",
						Source: types.DataSource{
							Name: "GitHub Advisory Database Maven",
							URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Amaven",
						},
					},
					Returns: db.OperationPutDataSourceReturns{},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
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
			putVulnerabilityID: []db.OperationPutVulnerabilityIDExpectation{
				{
					Args: db.OperationPutVulnerabilityIDArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2018-1196",
					},
				},
			},
		},
		{
			name:      "happy path pip uppercase",
			ecosystem: Pip,
			args: args{
				ghsas: []GithubSecurityAdvisory{
					{
						Severity:  "MODERATE",
						UpdatedAt: "2018-10-04T18:05:59Z",
						Package: Package{
							Ecosystem: "PIP",
							Name:      "Django",
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
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "GitHub Security Advisory Pip",
						PkgName:         "django",
						VulnerabilityID: "CVE-2018-14574",
						Advisory: types.Advisory{
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
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
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
			putDataSource: []db.OperationPutDataSourceExpectation{
				{
					Args: db.OperationPutDataSourceArgs{
						TxAnything: true,
						BktName:    "GitHub Security Advisory Pip",
						Source: types.DataSource{
							Name: "GitHub Advisory Database Pip",
							URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip",
						},
					},
					Returns: db.OperationPutDataSourceReturns{},
				},
			},
			putVulnerabilityID: []db.OperationPutVulnerabilityIDExpectation{
				{
					Args: db.OperationPutVulnerabilityIDArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2018-14574",
					},
				},
			},
		},
		{
			name:      "happy path pip hyphen",
			ecosystem: Pip,
			args: args{
				ghsas: []GithubSecurityAdvisory{
					{
						Severity:  "MODERATE",
						UpdatedAt: "2018-10-04T18:05:59Z",
						Package: Package{
							Ecosystem: "PIP",
							Name:      "dj_ango",
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
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "GitHub Security Advisory Pip",
						PkgName:         "dj-ango",
						VulnerabilityID: "CVE-2018-14574",
						Advisory: types.Advisory{
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
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
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
			putDataSource: []db.OperationPutDataSourceExpectation{
				{
					Args: db.OperationPutDataSourceArgs{
						TxAnything: true,
						BktName:    "GitHub Security Advisory Pip",
						Source: types.DataSource{
							Name: "GitHub Advisory Database Pip",
							URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip",
						},
					},
					Returns: db.OperationPutDataSourceReturns{},
				},
			},
			putVulnerabilityID: []db.OperationPutVulnerabilityIDExpectation{
				{
					Args: db.OperationPutVulnerabilityIDArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2018-14574",
					},
				},
			},
		},
		{
			name:      "happy path with empty PatchedVersion",
			ecosystem: Maven,
			args: args{
				ghsas: []GithubSecurityAdvisory{
					{
						Severity:  "HIGH",
						UpdatedAt: "2019-10-18T15:22:29Z",
						Package: Package{
							Ecosystem: "Maven",
							Name:      "com.fasterxml.jackson.core:jackson-databind",
						},
						Advisory: GhsaAdvisory{
							DatabaseId: 1950,
							Id:         "MDE2OlNlY3VyaXR5QWR2aXNvcnlHSFNBLWd3dzctcDV3NC13cmZ2",
							GhsaId:     "GHSA-gww7-p5w4-wrfv",
							References: []Reference{
								{
									Url: "https://nvd.nist.gov/vuln/detail/CVE-2019-20330",
								},
								{
									Url: "https://github.com/advisories/GHSA-gww7-p5w4-wrfv",
								},
							},
							Identifiers: []Identifier{
								{
									Type:  "GHSA",
									Value: "GHSA-gww7-p5w4-wrfv",
								},
								{
									Type:  "CVE",
									Value: "CVE-2019-20330",
								},
							},
							Description: "FasterXML jackson-databind 2.x before 2.9.10.2 lacks certain net.sf.ehcache blocking.",
							Origin:      "UNSPECIFIED",
							PublishedAt: "2020-03-04T20:52:11Z",
							Severity:    "HIGH",
							Summary:     "Deserialization of Untrusted Data in jackson-databind",
							UpdatedAt:   "2020-03-04T20:52:11Z",
							WithdrawnAt: "",
						},
						Versions: []Version{
							{
								FirstPatchedVersion: FirstPatchedVersion{
									Identifier: "2.9.10.2",
								},
								VulnerableVersionRange: "\u003e= 2.9.0, \u003c= 2.9.10.1",
							},
							{
								FirstPatchedVersion: FirstPatchedVersion{
									Identifier: "2.8.11.5",
								},
								VulnerableVersionRange: "\u003e= 2.8.0, \u003c= 2.8.11.4",
							},
							{
								FirstPatchedVersion: FirstPatchedVersion{
									Identifier: "",
								},
								VulnerableVersionRange: "\u003e= 2.7.0, \u003c= 2.7.9.6",
							},
							{
								FirstPatchedVersion: FirstPatchedVersion{
									Identifier: "",
								},
								VulnerableVersionRange: "\u003e= 2.6.0, \u003c= 2.6.7.3",
							},
						},
					},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "GitHub Security Advisory Maven",
						PkgName:         "com.fasterxml.jackson.core:jackson-databind",
						VulnerabilityID: "CVE-2019-20330",
						Advisory: types.Advisory{
							PatchedVersions: []string{"2.9.10.2", "2.8.11.5"},
							VulnerableVersions: []string{
								"\u003e= 2.9.0, \u003c= 2.9.10.1",
								"\u003e= 2.8.0, \u003c= 2.8.11.4",
								"\u003e= 2.7.0, \u003c= 2.7.9.6",
								"\u003e= 2.6.0, \u003c= 2.6.7.3",
							},
						},
					},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:      true,
						Source:          vulnerability.GHSAMaven,
						VulnerabilityID: "CVE-2019-20330",
						Vulnerability: types.VulnerabilityDetail{
							ID:       "CVE-2019-20330",
							Severity: types.SeverityHigh,
							References: []string{
								"https://nvd.nist.gov/vuln/detail/CVE-2019-20330",
								"https://github.com/advisories/GHSA-gww7-p5w4-wrfv",
							},
							Title:       "Deserialization of Untrusted Data in jackson-databind",
							Description: "FasterXML jackson-databind 2.x before 2.9.10.2 lacks certain net.sf.ehcache blocking.",
						},
					},
				},
			},
			putDataSource: []db.OperationPutDataSourceExpectation{
				{
					Args: db.OperationPutDataSourceArgs{
						TxAnything: true,
						BktName:    "GitHub Security Advisory Maven",
						Source: types.DataSource{
							Name: "GitHub Advisory Database Maven",
							URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Amaven",
						},
					},
					Returns: db.OperationPutDataSourceReturns{},
				},
			},
			putVulnerabilityID: []db.OperationPutVulnerabilityIDExpectation{
				{
					Args: db.OperationPutVulnerabilityIDArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2019-20330",
					},
				},
			},
		},
		{
			name:      "happy path with empty CVE-ID",
			ecosystem: Npm,
			args: args{
				ghsas: []GithubSecurityAdvisory{
					{
						Severity:  "MODERATE",
						UpdatedAt: "2019-10-18T15:22:29Z",
						Package: Package{
							Ecosystem: "NPM",
							Name:      "renovate",
						},
						Advisory: GhsaAdvisory{
							DatabaseId: 1749,
							Id:         "MDE2OlNlY3VyaXR5QWR2aXNvcnlHSFNBLXY3eDMtN2h3Ny1wY2pn",
							GhsaId:     "GHSA-v7x3-7hw7-pcjg",
							References: []Reference{
								{
									Url: "https://github.com/advisories/GHSA-v7x3-7hw7-pcjg",
								},
							},
							Identifiers: []Identifier{
								{
									Type:  "GHSA",
									Value: "GHSA-v7x3-7hw7-pcjg",
								},
								{
									Type:  "CVE",
									Value: "",
								},
							},
							Description: "## Go Modules Vulnerability Disclosure\\n\\n### Impact\\r\\n\\r\\nTemporary repository tokens were leaked into Pull Requests comments in during certain Go Modules update failure scenarios.\\r\\n\\r\\n### Patches\\r\\n\\r\\nThe problem has been patched. Self-hosted users should upgrade to v19.38.7 or later.\\r\\n\\r\\n### Workarounds\\r\\n\\r\\nDisable Go Modules support.\\r\\n\\r\\n### References\\r\\n\\r\\nBlog post: https://renovatebot.com/blog/go-modules-vulnerability-disclosure\\r\\n\\r\\n### For more information\\r\\n\\r\\nIf you have any questions or comments about this advisory:\\r\\n* Open an issue in [Renovate](http://github.com/renovatebot/renovate)\\r\\n* Email us at [support@renovatebot.com](mailto:support@renovatebot.com)\\r\\n\\n",
							Origin:      "UNSPECIFIED",
							PublishedAt: "2019-10-21T16:02:33",
							Severity:    "MODERATE",
							Summary:     "Moderate severity vulnerability that affects renovate",
							UpdatedAt:   "2019-10-21T16:02:33Z",
							WithdrawnAt: "",
						},
						Versions: []Version{
							{
								FirstPatchedVersion: FirstPatchedVersion{
									Identifier: "19.38.7",
								},
								VulnerableVersionRange: "\u003c 19.38.7",
							},
						},
					},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "GitHub Security Advisory Npm",
						PkgName:         "renovate",
						VulnerabilityID: "GHSA-v7x3-7hw7-pcjg",
						Advisory: types.Advisory{
							PatchedVersions:    []string{"19.38.7"},
							VulnerableVersions: []string{"< 19.38.7"},
						},
					},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:      true,
						Source:          vulnerability.GHSANpm,
						VulnerabilityID: "GHSA-v7x3-7hw7-pcjg",
						Vulnerability: types.VulnerabilityDetail{
							ID:          "GHSA-v7x3-7hw7-pcjg",
							Severity:    types.SeverityMedium,
							References:  []string{"https://github.com/advisories/GHSA-v7x3-7hw7-pcjg"},
							Title:       "Moderate severity vulnerability that affects renovate",
							Description: "## Go Modules Vulnerability Disclosure\\n\\n### Impact\\r\\n\\r\\nTemporary repository tokens were leaked into Pull Requests comments in during certain Go Modules update failure scenarios.\\r\\n\\r\\n### Patches\\r\\n\\r\\nThe problem has been patched. Self-hosted users should upgrade to v19.38.7 or later.\\r\\n\\r\\n### Workarounds\\r\\n\\r\\nDisable Go Modules support.\\r\\n\\r\\n### References\\r\\n\\r\\nBlog post: https://renovatebot.com/blog/go-modules-vulnerability-disclosure\\r\\n\\r\\n### For more information\\r\\n\\r\\nIf you have any questions or comments about this advisory:\\r\\n* Open an issue in [Renovate](http://github.com/renovatebot/renovate)\\r\\n* Email us at [support@renovatebot.com](mailto:support@renovatebot.com)\\r\\n\\n",
						},
					},
				},
			},
			putDataSource: []db.OperationPutDataSourceExpectation{
				{
					Args: db.OperationPutDataSourceArgs{
						TxAnything: true,
						BktName:    "GitHub Security Advisory Npm",
						Source: types.DataSource{
							Name: "GitHub Advisory Database Npm",
							URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm",
						},
					},
					Returns: db.OperationPutDataSourceReturns{},
				},
			},
			putVulnerabilityID: []db.OperationPutVulnerabilityIDExpectation{
				{
					Args: db.OperationPutVulnerabilityIDArgs{
						TxAnything:      true,
						VulnerabilityID: "GHSA-v7x3-7hw7-pcjg",
					},
				},
			},
		},
		{
			name:      "putAdvisoryDetail returns an error",
			ecosystem: RubyGems,
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
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "GitHub Security Advisory RubyGems",
						PkgName:         "activestorage",
						VulnerabilityID: "CVE-2018-16477",
						Advisory: types.Advisory{
							PatchedVersions:    []string{"5.2.1.1"},
							VulnerableVersions: []string{"\u003e= 5.2.0, \u003c 5.2.1.1"},
						},
					},
					Returns: db.OperationPutAdvisoryDetailReturns{
						Err: errors.New("error"),
					},
				},
			},
			putDataSource: []db.OperationPutDataSourceExpectation{
				{
					Args: db.OperationPutDataSourceArgs{
						TxAnything: true,
						BktName:    "GitHub Security Advisory RubyGems",
						Source: types.DataSource{
							Name: "GitHub Advisory Database RubyGems",
							URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Arubygems",
						},
					},
					Returns: db.OperationPutDataSourceReturns{},
				},
			},
			wantErr: "failed to save GHSA",
		},
		{
			name:      "PutVulnerabilityDetail returns an error",
			ecosystem: RubyGems,
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
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "GitHub Security Advisory RubyGems",
						PkgName:         "activestorage",
						VulnerabilityID: "CVE-2018-16477",
						Advisory: types.Advisory{
							PatchedVersions:    []string{"5.2.1.1"},
							VulnerableVersions: []string{"\u003e= 5.2.0, \u003c 5.2.1.1"},
						},
					},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
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
					Returns: db.OperationPutVulnerabilityDetailReturns{
						Err: errors.New("error"),
					},
				},
			},
			putDataSource: []db.OperationPutDataSourceExpectation{
				{
					Args: db.OperationPutDataSourceArgs{
						TxAnything: true,
						BktName:    "GitHub Security Advisory RubyGems",
						Source: types.DataSource{
							Name: "GitHub Advisory Database RubyGems",
							URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Arubygems",
						},
					},
					Returns: db.OperationPutDataSourceReturns{},
				},
			},
			wantErr: "failed to save GHSA vulnerability detail",
		},
		{
			name:      "PutVulnerabilitySeveiry returns an error",
			ecosystem: RubyGems,
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
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "GitHub Security Advisory RubyGems",
						PkgName:         "activestorage",
						VulnerabilityID: "CVE-2018-16477",
						Advisory: types.Advisory{
							PatchedVersions:    []string{"5.2.1.1"},
							VulnerableVersions: []string{"\u003e= 5.2.0, \u003c 5.2.1.1"},
						},
					},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
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
			putDataSource: []db.OperationPutDataSourceExpectation{
				{
					Args: db.OperationPutDataSourceArgs{
						TxAnything: true,
						BktName:    "GitHub Security Advisory RubyGems",
						Source: types.DataSource{
							Name: "GitHub Advisory Database RubyGems",
							URL:  "https://github.com/advisories?query=type%3Areviewed+ecosystem%3Arubygems",
						},
					},
					Returns: db.OperationPutDataSourceReturns{},
				},
			},
			putVulnerabilityID: []db.OperationPutVulnerabilityIDExpectation{
				{
					Args: db.OperationPutVulnerabilityIDArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2018-16477",
					},
					Returns: db.OperationPutVulnerabilityIDReturns{
						Err: errors.New("error"),
					},
				},
			},
			wantErr: "failed to save the vulnerability ID",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDBConfig := new(db.MockOperation)
			mockDBConfig.ApplyPutAdvisoryDetailExpectations(tt.putAdvisoryDetail)
			mockDBConfig.ApplyPutVulnerabilityDetailExpectations(tt.putVulnerabilityDetail)
			mockDBConfig.ApplyPutDataSourceExpectations(tt.putDataSource)
			mockDBConfig.ApplyPutVulnerabilityIDExpectations(tt.putVulnerabilityID)

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
