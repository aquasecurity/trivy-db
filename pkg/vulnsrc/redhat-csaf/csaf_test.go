package redhatcsaf_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	redhatcsaf "github.com/aquasecurity/trivy-db/pkg/vulnsrc/redhat-csaf"
	redhat "github.com/aquasecurity/trivy-db/pkg/vulnsrc/redhat-oval"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
)

func TestMain(m *testing.M) {
	utils.Quiet = true
	os.Exit(m.Run())
}

func TestVulnSrc_Update(t *testing.T) {
	tests := []struct {
		name       string
		dir        string
		wantValues []vulnsrctest.WantValues
		wantErr    string
	}{
		{
			name: "happy path",
			dir:  filepath.Join("testdata"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{
						"data-source",
						"Red Hat",
					},
					Value: types.DataSource{
						ID:   vulnerability.RedHatOVAL,
						Name: "Red Hat OVAL v2",
						URL:  "https://www.redhat.com/security/data/oval/v2/",
					},
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"0",
					},
					Value: "cpe:/a:redhat:enterprise_linux:7",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"1",
					},
					Value: "cpe:/a:redhat:enterprise_linux:8",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"2",
					},
					Value: "cpe:/a:redhat:enterprise_linux:8::appstream",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"3",
					},
					Value: "cpe:/a:redhat:enterprise_linux:8::crb",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"4",
					},
					Value: "cpe:/a:redhat:rhel_eus:8.1",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"5",
					},
					Value: "cpe:/o:redhat:enterprise_linux:7::server",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"6",
					},
					Value: "cpe:/o:redhat:enterprise_linux:8::baseos",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"repository",
						"rhel-8-for-x86_64-baseos-rpms",
					},
					Value: []int{6},
				},
				{
					Key: []string{
						"Red Hat CPE",
						"nvr",
						"3scale-amp-apicast-gateway-container-1.11-1-x86_64",
					},
					Value: []int{5},
				},
				{
					Key: []string{
						"advisory-detail",
						"RawEntry-2020-11879",
						"Red Hat",
						"evolution",
					},
					Value: redhat.Advisory{
						Entries: []redhat.Entry{
							{
								Status:             types.StatusWillNotFix,
								FixedVersion:       "",
								AffectedCPEIndices: []int{1},
								Cves: []redhat.CveEntry{
									{
										ID:       "",
										Severity: types.SeverityMedium,
									},
								},
							},
						},
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"RHSA-2020:5624",
						"Red Hat",
						"thunderbird",
					},
					Value: redhat.Advisory{
						Entries: []redhat.Entry{
							{
								FixedVersion: "0:78.6.0-1.el8_3",
								AffectedCPEIndices: []int{
									1,
									2,
									6,
								},
								Arches: []string{
									"aarch64",
									"ppc64le",
									"x86_64",
								},
								Cves: []redhat.CveEntry{
									{
										ID:       "RawEntry-2020-16042",
										Severity: types.SeverityHigh,
									},
									{
										ID:       "RawEntry-2020-26971",
										Severity: types.SeverityHigh,
									},
								},
							},
						},
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"RHSA-2020:5624",
						"Red Hat",
						"thunderbird-debugsource",
					},
					Value: redhat.Advisory{
						Entries: []redhat.Entry{
							{
								FixedVersion: "0:78.6.0-1.el8_3",
								AffectedCPEIndices: []int{
									1,
									2,
									6,
								},
								Arches: []string{
									"aarch64",
									"ppc64le",
									"x86_64",
								},
								Cves: []redhat.CveEntry{
									{
										ID:       "RawEntry-2020-16042",
										Severity: types.SeverityHigh,
									},
									{
										ID:       "RawEntry-2020-26971",
										Severity: types.SeverityHigh,
									},
								},
							},
						},
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"RHSA-2020:4751",
						"Red Hat",
						"httpd:2.4::httpd",
					},
					Value: redhat.Advisory{
						Entries: []redhat.Entry{
							{
								FixedVersion: "0:2.4.37-30.module+el7.3.0+7001+0766b9e7",
								AffectedCPEIndices: []int{
									0,
									5,
								},
								Arches: []string{
									"aarch64",
									"ppc64le",
									"s390x",
									"x86_64",
								},
								Cves: []redhat.CveEntry{
									{
										ID:       "RawEntry-2018-17189",
										Severity: types.SeverityCritical,
									},
								},
							},
							{
								FixedVersion: "0:2.4.37-30.module+el8.3.0+7001+0766b9e7",
								AffectedCPEIndices: []int{
									1,
									2,
								},
								Arches: []string{
									"aarch64",
									"ppc64le",
									"s390x",
									"x86_64",
								},
								Cves: []redhat.CveEntry{
									{
										ID:       "RawEntry-2018-17189",
										Severity: types.SeverityLow,
									},
								},
							},
						},
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"RawEntry-2020-14342",
						"Red Hat",
						"cifs-utils",
					},
					Value: redhat.Advisory{
						Entries: []redhat.Entry{
							{
								Status:       types.StatusAffected,
								FixedVersion: "",
								AffectedCPEIndices: []int{
									3,
									5,
								},
								Cves: []redhat.CveEntry{
									{
										Severity: types.SeverityLow,
									},
								},
							},
						},
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"RHSA-2020:9999",
						"Red Hat",
						"thunderbird",
					},
					Value: redhat.Advisory{
						Entries: []redhat.Entry{
							{
								FixedVersion:       "0:999.el8_3",
								AffectedCPEIndices: []int{4},
								Arches: []string{
									"aarch64",
									"ppc64le",
									"x86_64",
								},
								Cves: []redhat.CveEntry{
									{
										ID:       "RawEntry-2020-26971",
										Severity: types.SeverityCritical,
									},
									{
										ID:       "RawEntry-2020-26972",
										Severity: types.SeverityMedium,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := redhatcsaf.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
			})
		})
	}
}
