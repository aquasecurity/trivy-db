package redhatoval_test

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
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
			dir:  filepath.Join("testdata", "happy"),
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
						"CVE-2020-11879",
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
										ID:       "CVE-2020-16042",
										Severity: types.SeverityHigh,
									},
									{
										ID:       "CVE-2020-26971",
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
										ID:       "CVE-2020-16042",
										Severity: types.SeverityHigh,
									},
									{
										ID:       "CVE-2020-26971",
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
										ID:       "CVE-2018-17189",
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
										ID:       "CVE-2018-17189",
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
						"CVE-2020-14342",
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
										ID:       "CVE-2020-26971",
										Severity: types.SeverityCritical,
									},
									{
										ID:       "CVE-2020-26972",
										Severity: types.SeverityMedium,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "happy path with different severity for different platforms",
			dir:  filepath.Join("testdata", "different-severity"),
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
					Value: "cpe:/a:redhat:enterprise_linux:8",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"1",
					},
					Value: "cpe:/a:redhat:enterprise_linux:8::appstream",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"2",
					},
					Value: "cpe:/a:redhat:enterprise_linux:8::crb",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"3",
					},
					Value: "cpe:/a:redhat:enterprise_linux:8::highavailability",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"4",
					},
					Value: "cpe:/a:redhat:enterprise_linux:8::nfv",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"5",
					},
					Value: "cpe:/a:redhat:enterprise_linux:8::realtime",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"6",
					},
					Value: "cpe:/a:redhat:enterprise_linux:8::resilientstorage",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"7",
					},
					Value: "cpe:/a:redhat:enterprise_linux:8::sap",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"8",
					},
					Value: "cpe:/a:redhat:enterprise_linux:8::sap_hana",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"9",
					},
					Value: "cpe:/a:redhat:enterprise_linux:8::supplementary",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"10",
					},
					Value: "cpe:/a:redhat:rhel_extras:7",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"11",
					},
					Value: "cpe:/a:redhat:rhel_extras_oracle_java:7",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"12",
					},
					Value: "cpe:/a:redhat:rhel_extras_rt:7",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"13",
					},
					Value: "cpe:/a:redhat:rhel_extras_sap:7",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"14",
					},
					Value: "cpe:/a:redhat:rhel_extras_sap_hana:7",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"15",
					},
					Value: "cpe:/o:redhat:enterprise_linux:7",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"16",
					},
					Value: "cpe:/o:redhat:enterprise_linux:7::client",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"17",
					},
					Value: "cpe:/o:redhat:enterprise_linux:7::computenode",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"18",
					},
					Value: "cpe:/o:redhat:enterprise_linux:7::container",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"19",
					},
					Value: "cpe:/o:redhat:enterprise_linux:7::containers",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"20",
					},
					Value: "cpe:/o:redhat:enterprise_linux:7::server",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"21",
					},
					Value: "cpe:/o:redhat:enterprise_linux:7::workstation",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"repository",
						"rhel-8-for-x86_64-baseos-rpms",
					},
					Value: []int{23},
				},
				{
					Key: []string{
						"Red Hat CPE",
						"nvr",
						"3scale-amp-apicast-gateway-container-1.11-1-x86_64",
					},
					Value: []int{20},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2020-21674",
						"Red Hat",
						"bsdcpio",
					},
					Value: redhat.Advisory{
						Entries: []redhat.Entry{
							{
								FixedVersion: "",
								AffectedCPEIndices: []int{
									10,
									11,
									12,
									13,
									14,
									15,
									16,
									17,
									18,
									19,
									20,
									21,
								},
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
						"CVE-2020-21674",
						"Red Hat",
						"bsdtar",
					},
					Value: redhat.Advisory{
						Entries: []redhat.Entry{
							{
								FixedVersion: "",
								AffectedCPEIndices: []int{
									10,
									11,
									12,
									13,
									14,
									15,
									16,
									17,
									18,
									19,
									20,
									21,
								},
								Cves: []redhat.CveEntry{
									{
										ID:       "",
										Severity: types.SeverityMedium,
									},
								},
							},
							{
								FixedVersion: "",
								AffectedCPEIndices: []int{
									0,
									1,
									2,
									3,
									4,
									5,
									6,
									7,
									8,
									9,
									22,
									23,
								},
								Cves: []redhat.CveEntry{
									{
										ID:       "",
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
						"CVE-2020-21674",
						"Red Hat",
						"libarchive",
					},
					Value: redhat.Advisory{
						Entries: []redhat.Entry{
							{
								FixedVersion: "",
								AffectedCPEIndices: []int{
									10,
									11,
									12,
									13,
									14,
									15,
									16,
									17,
									18,
									19,
									20,
									21,
								},
								Cves: []redhat.CveEntry{
									{
										ID:       "",
										Severity: types.SeverityMedium,
									},
								},
							},
							{
								FixedVersion: "",
								AffectedCPEIndices: []int{
									0,
									1,
									2,
									3,
									4,
									5,
									6,
									7,
									8,
									9,
									22,
									23,
								},
								Cves: []redhat.CveEntry{
									{
										ID:       "",
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
						"CVE-2020-21674",
						"Red Hat",
						"libarchive-debugsource",
					},
					Value: redhat.Advisory{
						Entries: []redhat.Entry{
							{
								FixedVersion: "",
								AffectedCPEIndices: []int{
									0,
									1,
									2,
									3,
									4,
									5,
									6,
									7,
									8,
									9,
									22,
									23,
								},
								Cves: []redhat.CveEntry{
									{
										ID:       "",
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
						"CVE-2020-21674",
						"Red Hat",
						"libarchive-devel",
					},
					Value: redhat.Advisory{
						Entries: []redhat.Entry{
							{
								FixedVersion: "",
								AffectedCPEIndices: []int{
									10,
									11,
									12,
									13,
									14,
									15,
									16,
									17,
									18,
									19,
									20,
									21,
								},
								Cves: []redhat.CveEntry{
									{
										ID:       "",
										Severity: types.SeverityMedium,
									},
								},
							},
							{
								FixedVersion: "",
								AffectedCPEIndices: []int{
									0,
									1,
									2,
									3,
									4,
									5,
									6,
									7,
									8,
									9,
									22,
									23,
								},
								Cves: []redhat.CveEntry{
									{
										ID:       "",
										Severity: types.SeverityLow,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "no definitions dir",
			dir:  filepath.Join("testdata", "no-definitions"),
		},
		{
			name:    "repository-to-cpe is unavailable",
			dir:     filepath.Join("testdata", "no-repo-to-cpe"),
			wantErr: "no such file or directory",
		},
		{
			name:    "broken repo-to-cpe",
			dir:     filepath.Join("testdata", "broken-repo-to-cpe"),
			wantErr: "JSON parse error",
		},
		{
			name:    "broken JSON",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "failed to decode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := redhat.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
			})
		})
	}
}

func TestVulnSrc_Get(t *testing.T) {
	type args struct {
		pkgName      string
		repositories []string
		nvrs         []string
	}
	tests := []struct {
		name     string
		args     args
		fixtures []string
		want     []types.Advisory
		wantErr  string
	}{
		{
			name: "repository",
			args: args{
				pkgName:      "bind",
				repositories: []string{"rhel-8-for-x86_64-baseos-rpms"},
			},
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/cpe.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			want: []types.Advisory{
				{
					VulnerabilityID: "CVE-2017-3145",
					VendorIDs:       []string{"RHSA-2018:0488"},
					Severity:        types.SeverityHigh,
					FixedVersion:    "32:9.9.4-29.el7_2.8",
					Arches: []string{
						"i386",
						"ppc64",
						"x86_64",
					},
					DataSource: &types.DataSource{
						ID:   vulnerability.RedHatOVAL,
						Name: "Red Hat OVAL v2",
						URL:  "https://www.redhat.com/security/data/oval/v2/",
					},
				},
				{
					VulnerabilityID: "CVE-2020-8625",
					Severity:        types.SeverityLow,
					DataSource: &types.DataSource{
						ID:   vulnerability.RedHatOVAL,
						Name: "Red Hat OVAL v2",
						URL:  "https://www.redhat.com/security/data/oval/v2/",
					},
				},
			},
		},
		{
			name: "nvr",
			args: args{
				pkgName: "bind",
				nvrs:    []string{"ubi8-init-container-8.0-7-x86_64"},
			},
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/cpe.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			want: []types.Advisory{
				{
					VulnerabilityID: "CVE-2017-3145",
					VendorIDs:       []string{"RHSA-2018:0488"},
					Severity:        types.SeverityHigh,
					FixedVersion:    "32:9.9.4-29.el7_2.8",
					Arches: []string{
						"i386",
						"ppc64",
						"x86_64",
					},
					DataSource: &types.DataSource{
						ID:   vulnerability.RedHatOVAL,
						Name: "Red Hat OVAL v2",
						URL:  "https://www.redhat.com/security/data/oval/v2/",
					},
				},
				{
					VulnerabilityID: "CVE-2020-8625",
					Severity:        types.SeverityLow,
					DataSource: &types.DataSource{
						ID:   vulnerability.RedHatOVAL,
						Name: "Red Hat OVAL v2",
						URL:  "https://www.redhat.com/security/data/oval/v2/",
					},
				},
			},
		},
		{
			name: "no CPE match",
			args: args{
				pkgName:      "bind",
				repositories: []string{"3scale-amp-2-rpms-for-rhel-8-x86_64-debug-rpms"},
			},
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/cpe.yaml",
			},
			want: []types.Advisory(nil),
		},
		{
			// This case should not be happened
			name: "unknown repository",
			args: args{
				pkgName:      "bind",
				repositories: []string{"unknown"},
			},
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/cpe.yaml",
			},
			wantErr: "unable to find CPE indices.",
		},
		{
			name: "no advisory bucket",
			args: args{
				pkgName:      "bind",
				repositories: []string{"rhel-8-for-x86_64-baseos-rpms"},
			},
			fixtures: []string{"testdata/fixtures/cpe.yaml"},
			want:     []types.Advisory(nil),
		},
		{
			name: "no CPE bucket",
			args: args{
				pkgName:      "bind",
				repositories: []string{"rhel-8-for-x86_64-baseos-rpms"},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			wantErr:  "unable to find CPE indices.",
		},
		{
			name: "broken JSON",
			args: args{
				pkgName:      "bind",
				repositories: []string{"rhel-8-for-x86_64-baseos-rpms"},
			},
			fixtures: []string{
				"testdata/fixtures/broken.yaml",
				"testdata/fixtures/cpe.yaml",
			},
			want:    []types.Advisory(nil),
			wantErr: "failed to unmarshal advisory JSON",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			vs := redhat.NewVulnSrc()
			got, err := vs.Get(tt.args.pkgName, tt.args.repositories, tt.args.nvrs)

			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			sort.Slice(got, func(i, j int) bool {
				return got[i].VulnerabilityID < got[j].VulnerabilityID
			})

			// Compare
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
