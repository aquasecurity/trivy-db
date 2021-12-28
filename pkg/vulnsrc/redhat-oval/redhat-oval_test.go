package redhatoval_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	redhat "github.com/aquasecurity/trivy-db/pkg/vulnsrc/redhat-oval"
)

func TestMain(m *testing.M) {
	utils.Quiet = true
	os.Exit(m.Run())
}

func TestVulnSrc_Update(t *testing.T) {
	type want struct {
		key   []string
		value interface{}
	}

	tests := []struct {
		name     string
		cacheDir string
		wants    []want
		wantErr  string
	}{
		{
			name:     "happy path",
			cacheDir: filepath.Join("testdata", "happy"),
			wants: []want{
				{
					key:   []string{"Red Hat CPE", "cpe", "0"},
					value: "cpe:/a:redhat:enterprise_linux:7",
				},
				{
					key:   []string{"Red Hat CPE", "cpe", "1"},
					value: "cpe:/a:redhat:enterprise_linux:8",
				},
				{
					key:   []string{"Red Hat CPE", "cpe", "2"},
					value: "cpe:/a:redhat:enterprise_linux:8::appstream",
				},
				{
					key:   []string{"Red Hat CPE", "cpe", "3"},
					value: "cpe:/a:redhat:enterprise_linux:8::crb",
				},
				{
					key:   []string{"Red Hat CPE", "cpe", "4"},
					value: "cpe:/a:redhat:rhel_eus:8.1",
				},
				{
					key:   []string{"Red Hat CPE", "cpe", "5"},
					value: "cpe:/o:redhat:enterprise_linux:7::server",
				},
				{
					key:   []string{"Red Hat CPE", "cpe", "6"},
					value: "cpe:/o:redhat:enterprise_linux:8::baseos",
				},
				{
					key:   []string{"Red Hat CPE", "repository", "rhel-8-for-x86_64-baseos-rpms"},
					value: []int{6},
				},
				{
					key:   []string{"Red Hat CPE", "nvr", "3scale-amp-apicast-gateway-container-1.11-1-x86_64"},
					value: []int{5},
				},
				{
					key: []string{"advisory-detail", "RHSA-2020:5624", "Red Hat", "thunderbird"},
					value: redhat.Advisory{
						Entries: []redhat.Entry{
							{
								FixedVersion:       "0:78.6.0-1.el8_3",
								AffectedCPEIndices: []int{1, 2, 6},
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
					key: []string{"advisory-detail", "RHSA-2020:5624", "Red Hat", "thunderbird-debugsource"},
					value: redhat.Advisory{
						Entries: []redhat.Entry{
							{
								FixedVersion:       "0:78.6.0-1.el8_3",
								AffectedCPEIndices: []int{1, 2, 6},
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
					key: []string{"advisory-detail", "RHSA-2020:4751", "Red Hat", "httpd:2.4::httpd"},
					value: redhat.Advisory{
						Entries: []redhat.Entry{
							{
								FixedVersion:       "0:2.4.37-30.module+el7.3.0+7001+0766b9e7",
								AffectedCPEIndices: []int{0, 5},
								Cves: []redhat.CveEntry{
									{
										ID:       "CVE-2018-17189",
										Severity: types.SeverityCritical,
									},
								},
							},
							{
								FixedVersion:       "0:2.4.37-30.module+el8.3.0+7001+0766b9e7",
								AffectedCPEIndices: []int{1, 2},
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
					key: []string{"advisory-detail", "CVE-2020-14342", "Red Hat", "cifs-utils"},
					value: redhat.Advisory{
						Entries: []redhat.Entry{
							{
								FixedVersion:       "",
								AffectedCPEIndices: []int{3, 5},
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
					key: []string{"advisory-detail", "RHSA-2020:9999", "Red Hat", "thunderbird"},
					value: redhat.Advisory{
						Entries: []redhat.Entry{
							{
								FixedVersion:       "0:999.el8_3",
								AffectedCPEIndices: []int{4},
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
			name:     "no definitions dir",
			cacheDir: filepath.Join("testdata", "no-definitions"),
		},
		{
			name:     "repository-to-cpe is unavailable",
			cacheDir: filepath.Join("testdata", "no-repo-to-cpe"),
			wantErr:  "no such file or directory",
		},
		{
			name:     "broken repo-to-cpe",
			cacheDir: filepath.Join("testdata", "broken-repo-to-cpe"),
			wantErr:  "JSON parse error",
		},
		{
			name:     "broken JSON",
			cacheDir: filepath.Join("testdata", "sad"),
			wantErr:  "failed to decode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, db.Init(dir))

			vs := redhat.NewVulnSrc()
			err := vs.Update(tt.cacheDir)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			}

			require.NoError(t, err)
			require.NoError(t, db.Close())

			for _, w := range tt.wants {
				dbtest.JSONEq(t, db.Path(dir), w.key, w.value, w.key)
			}
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
			fixtures: []string{"testdata/fixtures/happy.yaml", "testdata/fixtures/cpe.yaml"},
			want: []types.Advisory{
				{
					VulnerabilityID: "CVE-2020-8625",
					Severity:        types.SeverityLow,
				},
				{
					VulnerabilityID: "CVE-2017-3145",
					VendorIDs:       []string{"RHSA-2018:0488"},
					Severity:        types.SeverityHigh,
					FixedVersion:    "32:9.9.4-29.el7_2.8",
				},
			},
		},
		{
			name: "nvr",
			args: args{
				pkgName: "bind",
				nvrs:    []string{"ubi8-init-container-8.0-7-x86_64"},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml", "testdata/fixtures/cpe.yaml"},
			want: []types.Advisory{
				{
					VulnerabilityID: "CVE-2020-8625",
					Severity:        types.SeverityLow,
				},
				{
					VulnerabilityID: "CVE-2017-3145",
					VendorIDs:       []string{"RHSA-2018:0488"},
					Severity:        types.SeverityHigh,
					FixedVersion:    "32:9.9.4-29.el7_2.8",
				},
				{
					VulnerabilityID: "CVE-2017-3145",
					VendorIDs:       []string{"RHSA-2018:0488"},
					Severity:        types.SeverityMedium,
					FixedVersion:    "32:9.9.4-50.el7_3.3",
				},
			},
		},
		{
			name: "no CPE match",
			args: args{
				pkgName:      "bind",
				repositories: []string{"3scale-amp-2-rpms-for-rhel-8-x86_64-debug-rpms"},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml", "testdata/fixtures/cpe.yaml"},
			want:     []types.Advisory(nil),
		},
		{
			// This case should not be happened
			name: "unknown repository",
			args: args{
				pkgName:      "bind",
				repositories: []string{"unknown"},
			},
			fixtures: []string{"testdata/fixtures/happy.yaml", "testdata/fixtures/cpe.yaml"},
			want:     []types.Advisory(nil),
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
			want:     []types.Advisory(nil),
		},
		{
			name: "broken JSON",
			args: args{
				pkgName:      "bind",
				repositories: []string{"rhel-8-for-x86_64-baseos-rpms"},
			},
			fixtures: []string{"testdata/fixtures/broken.yaml", "testdata/fixtures/cpe.yaml"},
			want:     []types.Advisory(nil),
			wantErr:  "failed to unmarshal advisory JSON",
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

			// Compare
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
