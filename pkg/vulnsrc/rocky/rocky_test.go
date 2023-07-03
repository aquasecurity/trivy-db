package rocky_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/rocky"
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
						"rocky 8",
					},
					Value: types.DataSource{
						ID:   vulnerability.Rocky,
						Name: "Rocky Linux updateinfo",
						URL:  "https://download.rockylinux.org/pub/rocky/",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2021-25215",
						"rocky 8",
						"bind-export-libs",
					},
					Value: types.Advisories{
						FixedVersion: "32:9.11.26-4.el8_4",
						Entries: []types.Advisory{
							{
								FixedVersion: "32:9.11.26-4.el8_4",
								Arches: []string{
									"aarch64",
									"i686",
									"x86_64",
								},
								VendorIDs: []string{"RLSA-2021:1989"},
							},
						},
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2021-25215",
						"rocky 8",
						"bind-export-devel",
					},
					Value: types.Advisories{
						FixedVersion: "32:9.11.26-4.el8_4",
						Entries: []types.Advisory{
							{
								FixedVersion: "32:9.11.26-4.el8_4",
								Arches: []string{
									"aarch64",
									"i686",
									"x86_64",
								},
								VendorIDs: []string{"RLSA-2021:1989"},
							},
						},
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2021-25215",
						string(vulnerability.Rocky),
					},
					Value: types.VulnerabilityDetail{
						Severity: types.SeverityHigh,
						References: []string{
							"https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-25215.json",
						},
						Title:       "Important: bind security update",
						Description: "For more information visit https://errata.rockylinux.org/RLSA-2021:1989",
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2021-25215",
					},
					Value: map[string]interface{}{},
				},
			},
		},
		{
			name: "happy path. Different versions",
			dir:  filepath.Join("testdata", "different-versions"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{
						"data-source",
						"rocky 8",
					},
					Value: types.DataSource{
						ID:   vulnerability.Rocky,
						Name: "Rocky Linux updateinfo",
						URL:  "https://download.rockylinux.org/pub/rocky/",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2021-25215",
						"rocky 8",
						"bind-export-devel",
					},
					Value: types.Advisories{
						FixedVersion: "32:7.11.26-4.el8_4",
						Entries: []types.Advisory{
							{
								FixedVersion: "32:9.11.26-4.el8_4",
								Arches: []string{
									"aarch64",
								},
								VendorIDs: []string{"RLSA-2021:000"},
							},
							{
								FixedVersion: "32:7.11.26-4.el8_4",
								Arches: []string{
									"x86_64",
								},
								VendorIDs: []string{"RLSA-2021:0000"},
							},
							{
								FixedVersion: "32:8.11.26-4.el8_4",
								Arches: []string{
									"i686",
								},
								VendorIDs: []string{"RLSA-2021:0000"},
							},
						},
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2021-25215",
						string(vulnerability.Rocky),
					},
					Value: types.VulnerabilityDetail{
						Severity: types.SeverityHigh,
						References: []string{
							"https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-25215.json",
						},
						Title:       "Important: bind security update",
						Description: "For more information visit https://errata.rockylinux.org/RLSA-2021:1989",
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2021-25215",
					},
					Value: map[string]interface{}{},
				},
			},
		},
		{
			name: "happy path. `noarch` package",
			dir:  filepath.Join("testdata", "noarch"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{
						"data-source",
						"rocky 9",
					},
					Value: types.DataSource{
						ID:   vulnerability.Rocky,
						Name: "Rocky Linux updateinfo",
						URL:  "https://download.rockylinux.org/pub/rocky/",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2022-42010",
						"rocky 9",
						"dbus-common",
					},
					Value: types.Advisories{
						FixedVersion: "1:1.12.20-7.el9_1",
						Entries: []types.Advisory{
							{
								FixedVersion: "1:1.12.20-7.el9_1",
								Arches: []string{
									"noarch",
								},
								VendorIDs: []string{"RLSA-2023:0335"},
							},
						},
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2022-42010",
						string(vulnerability.Rocky),
					},
					Value: types.VulnerabilityDetail{
						Severity: types.SeverityMedium,
						References: []string{
							"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-42010",
							"https://errata.rockylinux.org/RLSA-2023:0335",
						},
						Title:       "Moderate: dbus security update",
						Description: "D-Bus is a system for sending messages between applications...",
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2022-42010",
					},
					Value: map[string]interface{}{},
				},
			},
		},
		{
			name: "happy path. `aarch64` only",
			dir:  filepath.Join("testdata", "aarch64-only"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{
						"data-source",
						"rocky 8",
					},
					Value: types.DataSource{
						ID:   vulnerability.Rocky,
						Name: "Rocky Linux updateinfo",
						URL:  "https://download.rockylinux.org/pub/rocky/",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2021-25215",
						"rocky 8",
						"bind-export-devel",
					},
					Value: types.Advisories{
						FixedVersion: "0.0.0",
						Entries: []types.Advisory{
							{
								FixedVersion: "32:9.11.26-4.el8_4",
								Arches: []string{
									"aarch64",
								},
								VendorIDs: []string{"RLSA-2021:1989"},
							},
						},
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2021-25215",
						string(vulnerability.Rocky),
					},
					Value: types.VulnerabilityDetail{
						Severity: types.SeverityHigh,
						References: []string{
							"https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2021-25215.json",
						},
						Title:       "Important: bind security update",
						Description: "For more information visit https://errata.rockylinux.org/RLSA-2021:1989",
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2021-25215",
					},
					Value: map[string]interface{}{},
				},
			},
		},
		{
			name: "happy path with duplicates",
			dir:  filepath.Join("testdata", "duplicates"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{
						"data-source",
						"rocky 8",
					},
					Value: types.DataSource{
						ID:   vulnerability.Rocky,
						Name: "Rocky Linux updateinfo",
						URL:  "https://download.rockylinux.org/pub/rocky/",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2022-29117",
						"rocky 8",
						"aspnetcore-runtime-6.0",
					},
					Value: types.Advisories{
						FixedVersion: "6.0.5-1.el8_6",
						Entries: []types.Advisory{
							{
								FixedVersion: "6.0.5-1.el8_6",
								Arches: []string{
									"aarch64",
									"x86_64",
								},
								VendorIDs: []string{
									"RLSA-2022:0000",
									"RLSA-2022:2200",
								},
							},
						},
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2022-29117",
						string(vulnerability.Rocky),
					},
					Value: types.VulnerabilityDetail{
						Severity: types.SeverityHigh,
						References: []string{
							"https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2022-29117.json",
						},
						Title:       "Important: .NET 5.0 security, bug fix, and enhancement update",
						Description: "For more information visit https://errata.rockylinux.org/RLSA-2022:2200",
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2022-29117",
					},
					Value: map[string]interface{}{},
				},
			},
		},
		{
			name:       "skip advisories for modular package",
			dir:        filepath.Join("testdata", "modular"),
			wantValues: []vulnsrctest.WantValues{},
		},
		{
			name:    "sad path",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "failed to decode Rocky erratum",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := rocky.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
			})
		})
	}
}

func TestRocky_Get(t *testing.T) {
	type args struct {
		release string
		pkgName string
		arch    string
	}
	tests := []struct {
		name     string
		args     args
		fixtures []string
		want     []types.Advisory
		wantErr  require.ErrorAssertionFunc
	}{
		{
			name:     "the same fixed version",
			fixtures: []string{"testdata/fixtures/happy.yaml", "testdata/fixtures/data-source.yaml"},
			args: args{
				release: "9",
				pkgName: "bind",
				arch:    "x86_64",
			},
			want: []types.Advisory{
				{
					VulnerabilityID: "CVE-2022-0396",
					FixedVersion:    "32:9.16.23-0.9.el8.1",
					Arches: []string{
						"aarch64",
						"x86_64",
					},
					VendorIDs: []string{"RLSA-2022:7643"},
					DataSource: &types.DataSource{
						ID:   "rocky",
						Name: "Rocky Linux updateinfo",
						URL:  "https://download.rockylinux.org/pub/rocky/",
					},
				},
			},
			wantErr: require.NoError,
		},
		{
			name:     "different fixed versions for different arches",
			fixtures: []string{"testdata/fixtures/happy.yaml", "testdata/fixtures/data-source.yaml"},
			args: args{
				release: "9",
				pkgName: "rsyslog",
				arch:    "aarch64",
			},
			want: []types.Advisory{
				{
					VulnerabilityID: "CVE-2022-24903",
					FixedVersion:    "8.2102.0-7.el8_6.2",
					Arches: []string{
						"aarch64",
					},
					VendorIDs: []string{"RLSA-2022:4799"},
					DataSource: &types.DataSource{
						ID:   "rocky",
						Name: "Rocky Linux updateinfo",
						URL:  "https://download.rockylinux.org/pub/rocky/",
					},
				},
			},
			wantErr: require.NoError,
		},
		{
			name:     "old schema, no entries",
			fixtures: []string{"testdata/fixtures/old.yaml", "testdata/fixtures/data-source.yaml"},
			args: args{
				release: "9",
				pkgName: "bind",
				arch:    "aarch64",
			},
			want: []types.Advisory{
				{
					VulnerabilityID: "CVE-2022-0396",
					FixedVersion:    "32:9.16.23-0.9.el8.1",
					DataSource: &types.DataSource{
						ID:   "rocky",
						Name: "Rocky Linux updateinfo",
						URL:  "https://download.rockylinux.org/pub/rocky/",
					},
				},
			},
			wantErr: require.NoError,
		},
		{
			name:     "broken JSON",
			fixtures: []string{"testdata/fixtures/broken.yaml"},
			args: args{
				release: "9",
				pkgName: "bind",
				arch:    "aarch64",
			},
			wantErr: require.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			vs := rocky.NewVulnSrc()
			got, err := vs.Get(tt.args.release, tt.args.pkgName, tt.args.arch)

			tt.wantErr(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
