package glad

import (
	"errors"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			name: "cache dir doesn't exist",
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
			wantErr: "error in GLAD save",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDBConfig := new(db.MockOperation)
			mockDBConfig.ApplyBatchUpdateExpectations(tt.batchUpdate)

			vs := VulnSrc{
				dbc: mockDBConfig,
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
		glads []Advisory
	}
	tests := []struct {
		name                   string
		packageType            packageType
		args                   args
		putAdvisoryDetail      []db.OperationPutAdvisoryDetailExpectation
		putVulnerabilityDetail []db.OperationPutVulnerabilityDetailExpectation
		putSeverity            []db.OperationPutSeverityExpectation
		wantErr                string
	}{
		{
			name:        "happy path conan",
			packageType: Conan,
			args: args{
				glads: []Advisory{
					{
						Identifier:       "CVE-2020-14150",
						PackageSlug:      "conan/bison",
						Title:            "Uncontrolled Resource Consumption",
						Description:      "GNU Bison allows attackers to cause a denial of service (application crash).",
						Date:             "2020-08-31",
						Pubdate:          "2020-06-15",
						AffectedRange:    "\u003c3.5.4",
						FixedVersions:    []string{"3.7.1"},
						AffectedVersions: "All versions before 3.5.4",
						NotImpacted:      "All versions starting from 3.5.4",
						Solution:         "Upgrade to version 3.7.1 or above.",
						Urls: []string{
							"https://nvd.nist.gov/vuln/detail/CVE-2020-14150",
							"https://lists.gnu.org/archive/html/info-gnu/2020-04/msg00000.html",
						},
						CvssV2: "AV:L/AC:L/Au:N/C:N/I:N/A:P",
						CvssV3: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
						UUID:   "4dbbfb75-32ff-471f-ab41-22337dddd1c9",
					},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "conan::GitLab Advisory Database Conan",
						PkgName:         "bison",
						VulnerabilityID: "CVE-2020-14150",
						Advisory: types.Advisory{
							VulnerableVersions: []string{"\u003c3.5.4"},
							PatchedVersions:    []string{"3.7.1"},
						},
					},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:      true,
						Source:          vulnerability.GLAD,
						VulnerabilityID: "CVE-2020-14150",
						Vulnerability: types.VulnerabilityDetail{
							ID:       "CVE-2020-14150",
							Severity: types.SeverityUnknown,
							References: []string{
								"https://nvd.nist.gov/vuln/detail/CVE-2020-14150",
								"https://lists.gnu.org/archive/html/info-gnu/2020-04/msg00000.html",
							},
							Title:        "Uncontrolled Resource Consumption",
							Description:  "GNU Bison allows attackers to cause a denial of service (application crash).",
							CvssVector:   "AV:L/AC:L/Au:N/C:N/I:N/A:P",
							CvssVectorV3: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
						},
					},
				},
			},
			putSeverity: []db.OperationPutSeverityExpectation{
				{
					Args: db.OperationPutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2020-14150",
						Severity:        types.SeverityUnknown,
					},
				},
			},
		},
		{
			name:        "happy path gem",
			packageType: Gem,
			args: args{
				glads: []Advisory{
					{
						Identifier:       "OSVDB-112347",
						PackageSlug:      "gem/activejob",
						Title:            "Object Injection",
						Description:      "A flaw in Active Job that can allow string arguments to be deserialized as if they were Global IDs. This may allow a remote attacker to inject arbitrary objects.",
						Date:             "2014-09-29",
						Pubdate:          "2014-09-29",
						AffectedRange:    "=4.2.0.beta1",
						FixedVersions:    []string{"4.2.0.beta2"},
						AffectedVersions: "Version 4.2.0.beta1",
						NotImpacted:      "",
						Solution:         "Upgrade to latest version.",
						Urls: []string{
							"http://weblog.rubyonrails.org/2014/9/29/Rails-4-2-0-beta2-has-been-released/",
						},
						CvssV2: "",
						CvssV3: "",
						UUID:   "a5939986-2994-4350-b1e5-db5506c136d1",
					},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "rubygems::GitLab Advisory Database Gem",
						PkgName:         "activejob",
						VulnerabilityID: "OSVDB-112347",
						Advisory: types.Advisory{
							VulnerableVersions: []string{"=4.2.0.beta1"},
							PatchedVersions:    []string{"4.2.0.beta2"},
						},
					},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:      true,
						Source:          vulnerability.GLAD,
						VulnerabilityID: "OSVDB-112347",
						Vulnerability: types.VulnerabilityDetail{
							ID:       "OSVDB-112347",
							Severity: types.SeverityUnknown,
							References: []string{
								"http://weblog.rubyonrails.org/2014/9/29/Rails-4-2-0-beta2-has-been-released/",
							},
							Title:        "Object Injection",
							Description:  "A flaw in Active Job that can allow string arguments to be deserialized as if they were Global IDs. This may allow a remote attacker to inject arbitrary objects.",
							CvssVector:   "",
							CvssVectorV3: "",
						},
					},
				},
			},
			putSeverity: []db.OperationPutSeverityExpectation{
				{
					Args: db.OperationPutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "OSVDB-112347",
						Severity:        types.SeverityUnknown,
					},
				},
			},
		},
		{
			name:        "happy path go",
			packageType: Go,
			args: args{
				glads: []Advisory{
					{
						Identifier:       "CVE-2016-1905",
						PackageSlug:      "go/k8s.io/kubernetes",
						Title:            "Improper Access Control",
						Description:      "The API server in Kubernetes does not properly check admission control, which allows remote authenticated users to access additional resources via a crafted patched object.",
						Date:             "2016-06-15",
						Pubdate:          "2016-02-03",
						AffectedRange:    "\u003cv1.2.0",
						FixedVersions:    []string{"v1.2.0"},
						AffectedVersions: "All versions before 1.2.0",
						NotImpacted:      "All version starting from 1.2.0",
						Solution:         "Upgrade to version 1.2.0",
						Urls: []string{
							"https://nvd.nist.gov/vuln/detail/CVE-2016-1905",
						},
						CvssV2: "AV:N/AC:L/Au:S/C:N/I:P/A:N",
						CvssV3: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N",
						UUID:   "86240c4b-d70a-4321-8364-ab87d9d46240",
					},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "go::GitLab Advisory Database Go",
						PkgName:         "k8s.io/kubernetes",
						VulnerabilityID: "CVE-2016-1905",
						Advisory: types.Advisory{
							VulnerableVersions: []string{"\u003cv1.2.0"},
							PatchedVersions:    []string{"v1.2.0"},
						},
					},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:      true,
						Source:          vulnerability.GLAD,
						VulnerabilityID: "CVE-2016-1905",
						Vulnerability: types.VulnerabilityDetail{
							ID:       "CVE-2016-1905",
							Severity: types.SeverityUnknown,
							References: []string{
								"https://nvd.nist.gov/vuln/detail/CVE-2016-1905",
							},
							Title:        "Improper Access Control",
							Description:  "The API server in Kubernetes does not properly check admission control, which allows remote authenticated users to access additional resources via a crafted patched object.",
							CvssVector:   "AV:N/AC:L/Au:S/C:N/I:P/A:N",
							CvssVectorV3: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N",
						},
					},
				},
			},
			putSeverity: []db.OperationPutSeverityExpectation{
				{
					Args: db.OperationPutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2016-1905",
						Severity:        types.SeverityUnknown,
					},
				},
			},
		},
		{
			name:        "happy path maven",
			packageType: Maven,
			args: args{
				glads: []Advisory{
					{
						Identifier:       "CVE-2018-1196",
						PackageSlug:      "maven/org.springframework.boot/spring-boot",
						Title:            "Symlink privilege escalation attack via Spring Boot launch script",
						Description:      "Spring Boot supports an embedded launch script that can be used to easily run the application as a systemd or init.d linux service. The script included with Spring Boot is susceptible to a symlink attack which allows the `run_user` to overwrite and take ownership of any file on the same system. In order to instigate the attack, the application must be installed as a service and the `run_user` requires shell access to the server.",
						Date:             "2018-04-20",
						Pubdate:          "2018-03-19",
						AffectedRange:    "(,1.5.10)",
						FixedVersions:    []string{"1.5.10.RELEASE"},
						AffectedVersions: "All versions before 1.5.10",
						NotImpacted:      "Spring Boot application that are not installed as a service, or are not using the embedded launch script are not susceptible.",
						Solution:         "Upgrade to the latest version",
						Urls:             []string{"https://pivotal.io/security/cve-2018-1196"},
						CvssV2:           "AV:N/AC:M/Au:N/C:N/I:P/A:N",
						CvssV3:           "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
						UUID:             "b6021cbc-1e37-41d4-80c2-d62d4aea3aec",
					},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "maven::GitLab Advisory Database Maven",
						PkgName:         "org.springframework.boot:spring-boot",
						VulnerabilityID: "CVE-2018-1196",
						Advisory: types.Advisory{
							VulnerableVersions: []string{"(,1.5.10)"},
							PatchedVersions:    []string{"1.5.10.RELEASE"},
						},
					},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:      true,
						Source:          vulnerability.GLAD,
						VulnerabilityID: "CVE-2018-1196",
						Vulnerability: types.VulnerabilityDetail{
							ID:       "CVE-2018-1196",
							Severity: types.SeverityUnknown,
							References: []string{
								"https://pivotal.io/security/cve-2018-1196",
							},
							Title:        "Symlink privilege escalation attack via Spring Boot launch script",
							Description:  "Spring Boot supports an embedded launch script that can be used to easily run the application as a systemd or init.d linux service. The script included with Spring Boot is susceptible to a symlink attack which allows the `run_user` to overwrite and take ownership of any file on the same system. In order to instigate the attack, the application must be installed as a service and the `run_user` requires shell access to the server.",
							CvssVector:   "AV:N/AC:M/Au:N/C:N/I:P/A:N",
							CvssVectorV3: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
						},
					},
				},
			},
			putSeverity: []db.OperationPutSeverityExpectation{
				{
					Args: db.OperationPutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2018-1196",
						Severity:        types.SeverityUnknown,
					},
				},
			},
		},
		{
			name:        "happy path npm",
			packageType: Npm,
			args: args{
				glads: []Advisory{
					{
						Identifier:       "CVE-2019-10742",
						PackageSlug:      "npm/axios",
						Title:            "Denial of Service",
						Description:      "Axios allows attackers to cause a denial of service (application crash) by continuing to accepting content after `maxContentLength` is exceeded.",
						Date:             "2019-05-08",
						Pubdate:          "2019-05-07",
						AffectedRange:    "\u003c=0.18.0",
						FixedVersions:    []string{"0.18.1"},
						AffectedVersions: "All versions up to 0.18.0",
						NotImpacted:      "All versions after 0.18.0",
						Solution:         "Upgrade to version 0.18.1 or above.",
						Urls: []string{
							"https://nvd.nist.gov/vuln/detail/CVE-2019-10742",
							"https://github.com/axios/axios/issues/1098",
							"https://github.com/axios/axios/pull/1485",
						},
						CvssV2: "AV:N/AC:L/Au:N/C:N/I:N/A:P",
						CvssV3: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
						UUID:   "b795b004-9d4a-49f2-a096-67b41809bf07",
					},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "npm::GitLab Advisory Database Npm",
						PkgName:         "axios",
						VulnerabilityID: "CVE-2019-10742",
						Advisory: types.Advisory{
							VulnerableVersions: []string{"\u003c=0.18.0"},
							PatchedVersions:    []string{"0.18.1"},
						},
					},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:      true,
						Source:          vulnerability.GLAD,
						VulnerabilityID: "CVE-2019-10742",
						Vulnerability: types.VulnerabilityDetail{
							ID:       "CVE-2019-10742",
							Severity: types.SeverityUnknown,
							References: []string{
								"https://nvd.nist.gov/vuln/detail/CVE-2019-10742",
								"https://github.com/axios/axios/issues/1098",
								"https://github.com/axios/axios/pull/1485",
							},
							Title:        "Denial of Service",
							Description:  "Axios allows attackers to cause a denial of service (application crash) by continuing to accepting content after `maxContentLength` is exceeded.",
							CvssVector:   "AV:N/AC:L/Au:N/C:N/I:N/A:P",
							CvssVectorV3: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
						},
					},
				},
			},
			putSeverity: []db.OperationPutSeverityExpectation{
				{
					Args: db.OperationPutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2019-10742",
						Severity:        types.SeverityUnknown,
					},
				},
			},
		},
		{
			name:        "happy path nuget",
			packageType: Nuget,
			args: args{
				glads: []Advisory{
					{
						Identifier:       "CVE-2020-1108",
						PackageSlug:      "nuget/powershell",
						Title:            "Uncontrolled Resource Consumption",
						Description:      "A denial of service vulnerability exists when dotnet Core or dotnet Framework improperly handles web requests.",
						Date:             "2020-12-08",
						Pubdate:          "2020-05-21",
						AffectedRange:    "[7.0]",
						FixedVersions:    []string{"7.1.0"},
						AffectedVersions: "Version 7.0",
						NotImpacted:      "All versions after 7.0",
						Solution:         "Upgrade to version 7.1.0 or above.",
						Urls: []string{
							"https://nvd.nist.gov/vuln/detail/CVE-2020-1108",
							"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1108",
						},
						CvssV2: "AV:N/AC:L/Au:N/C:N/I:N/A:P",
						CvssV3: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
						UUID:   "ae7e19e6-c878-4bb7-b09a-2c747827b6d3",
					},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "nuget::GitLab Advisory Database Nuget",
						PkgName:         "powershell",
						VulnerabilityID: "CVE-2020-1108",
						Advisory: types.Advisory{
							VulnerableVersions: []string{"[7.0]"},
							PatchedVersions:    []string{"7.1.0"},
						},
					},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:      true,
						Source:          vulnerability.GLAD,
						VulnerabilityID: "CVE-2020-1108",
						Vulnerability: types.VulnerabilityDetail{
							ID:       "CVE-2020-1108",
							Severity: types.SeverityUnknown,
							References: []string{
								"https://nvd.nist.gov/vuln/detail/CVE-2020-1108",
								"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1108",
							},
							Title:        "Uncontrolled Resource Consumption",
							Description:  "A denial of service vulnerability exists when dotnet Core or dotnet Framework improperly handles web requests.",
							CvssVector:   "AV:N/AC:L/Au:N/C:N/I:N/A:P",
							CvssVectorV3: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
						},
					},
				},
			},
			putSeverity: []db.OperationPutSeverityExpectation{
				{
					Args: db.OperationPutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2020-1108",
						Severity:        types.SeverityUnknown,
					},
				},
			},
		},
		{
			name:        "happy path packagist",
			packageType: Packagist,
			args: args{
				glads: []Advisory{
					{
						Identifier:       "GMS-2018-25",
						PackageSlug:      "packagist/adodb/adodb-php",
						Title:            "SQL Injection",
						Description:      "The `SelectLimit` function has a potential SQL injection vulnerability through the use of the `nrows` and `offset` parameters which are not forced to integers.",
						Date:             "2018-03-06",
						Pubdate:          "2018-03-06",
						AffectedRange:    "\u003c5.20.11",
						FixedVersions:    []string{"v5.20.11"},
						AffectedVersions: "All versions before 5.20.11",
						NotImpacted:      "",
						Solution:         "Upgrade to latest version.",
						Urls: []string{
							"https://github.com/ADOdb/ADOdb/commit/d29c23f2264ec95c6d3851e0f51ce240b2f36b74",
							"https://github.com/ADOdb/ADOdb/issues/400",
							"https://github.com/ADOdb/ADOdb/pull/401",
						},
						CvssV2: "",
						CvssV3: "",
						UUID:   "93b94640-8419-436d-9874-fe2bb112b8fa",
					},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "composer::GitLab Advisory Database Packagist",
						PkgName:         "adodb/adodb-php",
						VulnerabilityID: "GMS-2018-25",
						Advisory: types.Advisory{
							VulnerableVersions: []string{"\u003c5.20.11"},
							PatchedVersions:    []string{"v5.20.11"},
						},
					},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:      true,
						Source:          vulnerability.GLAD,
						VulnerabilityID: "GMS-2018-25",
						Vulnerability: types.VulnerabilityDetail{
							ID:       "GMS-2018-25",
							Severity: types.SeverityUnknown,
							References: []string{
								"https://github.com/ADOdb/ADOdb/commit/d29c23f2264ec95c6d3851e0f51ce240b2f36b74",
								"https://github.com/ADOdb/ADOdb/issues/400",
								"https://github.com/ADOdb/ADOdb/pull/401",
							},
							Title:        "SQL Injection",
							Description:  "The `SelectLimit` function has a potential SQL injection vulnerability through the use of the `nrows` and `offset` parameters which are not forced to integers.",
							CvssVector:   "",
							CvssVectorV3: "",
						},
					},
				},
			},
			putSeverity: []db.OperationPutSeverityExpectation{
				{
					Args: db.OperationPutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "GMS-2018-25",
						Severity:        types.SeverityUnknown,
					},
				},
			},
		},
		{
			name:        "happy path pypi",
			packageType: PyPI,
			args: args{
				glads: []Advisory{
					{
						Identifier:    "CVE-2020-13254",
						PackageSlug:   "pypi/Django",
						Title:         "Improper Certificate Validation",
						Description:   "In cases where a memcached backend does not perform key validation, passing malformed cache keys could result in a key collision, and potential data leakage.",
						Date:          "2021-01-20",
						Pubdate:       "2020-06-03",
						AffectedRange: "\u003e=2.2,\u003c2.2.13||\u003e=3.0,\u003c3.0.7",
						FixedVersions: []string{
							"2.2.13",
							"3.0.7",
						},
						AffectedVersions: "All versions starting from 2.2 before 2.2.13, all versions starting from 3.0 before 3.0.7",
						NotImpacted:      "All versions before 2.2, all versions starting from 2.2.13 before 3.0, all versions starting from 3.0.7",
						Solution:         "Upgrade to versions 2.2.13, 3.0.7 or above.",
						Urls: []string{

							"https://nvd.nist.gov/vuln/detail/CVE-2020-13254",
							"https://docs.djangoproject.com/en/3.0/releases/security/",
							"https://www.djangoproject.com/weblog/2020/jun/03/security-releases/",
						},
						CvssV2: "AV:N/AC:M/Au:N/C:P/I:N/A:N",
						CvssV3: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
						UUID:   "f2e049cc-5afd-4729-9b12-c7c4b3a86d3a",
					},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "pip::GitLab Advisory Database PyPI",
						PkgName:         "Django",
						VulnerabilityID: "CVE-2020-13254",
						Advisory: types.Advisory{
							VulnerableVersions: []string{"\u003e=2.2,\u003c2.2.13||\u003e=3.0,\u003c3.0.7"},
							PatchedVersions: []string{
								"2.2.13",
								"3.0.7",
							},
						},
					},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:      true,
						Source:          vulnerability.GLAD,
						VulnerabilityID: "CVE-2020-13254",
						Vulnerability: types.VulnerabilityDetail{
							ID:       "CVE-2020-13254",
							Severity: types.SeverityUnknown,
							References: []string{
								"https://nvd.nist.gov/vuln/detail/CVE-2020-13254",
								"https://docs.djangoproject.com/en/3.0/releases/security/",
								"https://www.djangoproject.com/weblog/2020/jun/03/security-releases/",
							},
							Title:        "Improper Certificate Validation",
							Description:  "In cases where a memcached backend does not perform key validation, passing malformed cache keys could result in a key collision, and potential data leakage.",
							CvssVector:   "AV:N/AC:M/Au:N/C:P/I:N/A:N",
							CvssVectorV3: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
						},
					},
				},
			},
			putSeverity: []db.OperationPutSeverityExpectation{
				{
					Args: db.OperationPutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2020-13254",
						Severity:        types.SeverityUnknown,
					},
				},
			},
		},
		{
			name:        "PutVulnerabilityDetail returns an error",
			packageType: PyPI,
			args: args{
				glads: []Advisory{
					{
						Identifier:    "CVE-2020-13254",
						PackageSlug:   "pypi/Django",
						Title:         "Improper Certificate Validation",
						Description:   "In cases where a memcached backend does not perform key validation, passing malformed cache keys could result in a key collision, and potential data leakage.",
						Date:          "2021-01-20",
						Pubdate:       "2020-06-03",
						AffectedRange: "\u003e=2.2,\u003c2.2.13||\u003e=3.0,\u003c3.0.7",
						FixedVersions: []string{
							"2.2.13",
							"3.0.7",
						},
						AffectedVersions: "All versions starting from 2.2 before 2.2.13, all versions starting from 3.0 before 3.0.7",
						NotImpacted:      "All versions before 2.2, all versions starting from 2.2.13 before 3.0, all versions starting from 3.0.7",
						Solution:         "Upgrade to versions 2.2.13, 3.0.7 or above.",
						Urls: []string{

							"https://nvd.nist.gov/vuln/detail/CVE-2020-13254",
							"https://docs.djangoproject.com/en/3.0/releases/security/",
							"https://www.djangoproject.com/weblog/2020/jun/03/security-releases/",
						},
						CvssV2: "AV:N/AC:M/Au:N/C:P/I:N/A:N",
						CvssV3: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
						UUID:   "f2e049cc-5afd-4729-9b12-c7c4b3a86d3a",
					},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "pip::GitLab Advisory Database PyPI",
						PkgName:         "Django",
						VulnerabilityID: "CVE-2020-13254",
						Advisory: types.Advisory{
							VulnerableVersions: []string{"\u003e=2.2,\u003c2.2.13||\u003e=3.0,\u003c3.0.7"},
							PatchedVersions: []string{
								"2.2.13",
								"3.0.7",
							},
						},
					},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:      true,
						Source:          vulnerability.GLAD,
						VulnerabilityID: "CVE-2020-13254",
						Vulnerability: types.VulnerabilityDetail{
							ID:       "CVE-2020-13254",
							Severity: types.SeverityUnknown,
							References: []string{
								"https://nvd.nist.gov/vuln/detail/CVE-2020-13254",
								"https://docs.djangoproject.com/en/3.0/releases/security/",
								"https://www.djangoproject.com/weblog/2020/jun/03/security-releases/",
							},
							Title:        "Improper Certificate Validation",
							Description:  "In cases where a memcached backend does not perform key validation, passing malformed cache keys could result in a key collision, and potential data leakage.",
							CvssVector:   "AV:N/AC:M/Au:N/C:P/I:N/A:N",
							CvssVectorV3: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
						},
					},
					Returns: db.OperationPutVulnerabilityDetailReturns{
						Err: errors.New("error"),
					},
				},
			},
			wantErr: "failed to save GLAD vulnerability detail",
		},
		{
			name:        "PutVulnerabilitySeverity returns an error",
			packageType: PyPI,
			args: args{
				glads: []Advisory{
					{
						Identifier:    "CVE-2020-13254",
						PackageSlug:   "pypi/Django",
						Title:         "Improper Certificate Validation",
						Description:   "In cases where a memcached backend does not perform key validation, passing malformed cache keys could result in a key collision, and potential data leakage.",
						Date:          "2021-01-20",
						Pubdate:       "2020-06-03",
						AffectedRange: "\u003e=2.2,\u003c2.2.13||\u003e=3.0,\u003c3.0.7",
						FixedVersions: []string{
							"2.2.13",
							"3.0.7",
						},
						AffectedVersions: "All versions starting from 2.2 before 2.2.13, all versions starting from 3.0 before 3.0.7",
						NotImpacted:      "All versions before 2.2, all versions starting from 2.2.13 before 3.0, all versions starting from 3.0.7",
						Solution:         "Upgrade to versions 2.2.13, 3.0.7 or above.",
						Urls: []string{

							"https://nvd.nist.gov/vuln/detail/CVE-2020-13254",
							"https://docs.djangoproject.com/en/3.0/releases/security/",
							"https://www.djangoproject.com/weblog/2020/jun/03/security-releases/",
						},
						CvssV2: "AV:N/AC:M/Au:N/C:P/I:N/A:N",
						CvssV3: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
						UUID:   "f2e049cc-5afd-4729-9b12-c7c4b3a86d3a",
					},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "pip::GitLab Advisory Database PyPI",
						PkgName:         "Django",
						VulnerabilityID: "CVE-2020-13254",
						Advisory: types.Advisory{
							VulnerableVersions: []string{"\u003e=2.2,\u003c2.2.13||\u003e=3.0,\u003c3.0.7"},
							PatchedVersions: []string{
								"2.2.13",
								"3.0.7",
							},
						},
					},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:      true,
						Source:          vulnerability.GLAD,
						VulnerabilityID: "CVE-2020-13254",
						Vulnerability: types.VulnerabilityDetail{
							ID:       "CVE-2020-13254",
							Severity: types.SeverityUnknown,
							References: []string{
								"https://nvd.nist.gov/vuln/detail/CVE-2020-13254",
								"https://docs.djangoproject.com/en/3.0/releases/security/",
								"https://www.djangoproject.com/weblog/2020/jun/03/security-releases/",
							},
							Title:        "Improper Certificate Validation",
							Description:  "In cases where a memcached backend does not perform key validation, passing malformed cache keys could result in a key collision, and potential data leakage.",
							CvssVector:   "AV:N/AC:M/Au:N/C:P/I:N/A:N",
							CvssVectorV3: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
						},
					},
				},
			},
			putSeverity: []db.OperationPutSeverityExpectation{
				{
					Args: db.OperationPutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2020-13254",
						Severity:        types.SeverityUnknown,
					},
					Returns: db.OperationPutSeverityReturns{
						Err: errors.New("error"),
					},
				},
			},
			wantErr: "failed to save GLAD vulnerability severity",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDBConfig := new(db.MockOperation)
			mockDBConfig.ApplyPutAdvisoryDetailExpectations(tt.putAdvisoryDetail)
			mockDBConfig.ApplyPutVulnerabilityDetailExpectations(tt.putVulnerabilityDetail)
			mockDBConfig.ApplyPutSeverityExpectations(tt.putSeverity)

			vs := VulnSrc{
				dbc: mockDBConfig,
			}
			err := vs.commit(nil, tt.packageType, tt.args.glads)

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
