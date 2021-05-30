package redhatoval

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
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

	testCases := []struct {
		name            string
		cacheDir        string
		repositoryToCPE string
		wants           []want
		wantErr         string
	}{
		{
			name:     "happy path",
			cacheDir: filepath.Join("testdata", "happy"),
			repositoryToCPE: `
				{
				  "data": {
				    "rhel-8-for-x86_64-baseos-rpms": {
				      "cpes": ["cpe:/o:redhat:enterprise_linux:8::baseos"]
				    }
				  }
				}`,
			wants: []want{
				{
					key:   []string{"Red Hat CPE", "rhel-8-for-x86_64-baseos-rpms"},
					value: []string{"cpe:/o:redhat:enterprise_linux:8::baseos"},
				},
				{
					key: []string{"advisory-detail", "CVE-2020-16042", "Red Hat Enterprise Linux 8", "thunderbird"},
					value: advisory{
						Advisory: types.Advisory{
							FixedVersion: "0:78.6.0-1.el8_3",
						},
						Definitions: []Definition{
							{
								FixedVersion: "0:78.6.0-1.el8_3",
								AffectedCPEList: []string{
									"cpe:/a:redhat:enterprise_linux:8",
									"cpe:/a:redhat:enterprise_linux:8::appstream",
								},
								AdvisoryID: "RHSA-2020:5624",
							},
						},
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2020-16042", "Red Hat Enterprise Linux 8", "thunderbird-debugsource"},
					value: advisory{
						Advisory: types.Advisory{
							FixedVersion: "0:78.6.0-1.el8_3",
						},
						Definitions: []Definition{
							{
								FixedVersion: "0:78.6.0-1.el8_3",
								AffectedCPEList: []string{
									"cpe:/a:redhat:enterprise_linux:8",
									"cpe:/a:redhat:enterprise_linux:8::appstream",
								},
								AdvisoryID: "RHSA-2020:5624",
							},
						},
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2020-26971", "Red Hat Enterprise Linux 8", "thunderbird"},
					value: advisory{
						Advisory: types.Advisory{
							FixedVersion: "0:78.6.0-1.el8_3",
						},
						Definitions: []Definition{
							{
								FixedVersion: "0:78.6.0-1.el8_3",
								AffectedCPEList: []string{
									"cpe:/a:redhat:enterprise_linux:8",
									"cpe:/a:redhat:enterprise_linux:8::appstream",
								},
								AdvisoryID: "RHSA-2020:5624",
							},
							{
								FixedVersion: "0:999.el8_3",
								AffectedCPEList: []string{
									"cpe:/a:redhat:rhel_eus:8.1",
									"cpe:/a:redhat:rhel_eus:8.1::appstream",
								},
								AdvisoryID: "RHSA-2020:9999",
							},
						},
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2020-26971", "Red Hat Enterprise Linux 8", "thunderbird"},
					value: advisory{
						Advisory: types.Advisory{
							FixedVersion: "0:78.6.0-1.el8_3",
						},
						Definitions: []Definition{
							{
								FixedVersion: "0:78.6.0-1.el8_3",
								AffectedCPEList: []string{
									"cpe:/a:redhat:enterprise_linux:8",
									"cpe:/a:redhat:enterprise_linux:8::appstream",
								},
								AdvisoryID: "RHSA-2020:5624",
							},
							{
								FixedVersion: "0:999.el8_3",
								AffectedCPEList: []string{
									"cpe:/a:redhat:rhel_eus:8.1",
									"cpe:/a:redhat:rhel_eus:8.1::appstream",
								},
								AdvisoryID: "RHSA-2020:9999",
							},
						},
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2020-26972", "Red Hat Enterprise Linux 8", "thunderbird"},
					value: advisory{
						Advisory: types.Advisory{
							FixedVersion: "0",
						},
						Definitions: []Definition{
							{
								FixedVersion: "0:999.el8_3",
								AffectedCPEList: []string{
									"cpe:/a:redhat:rhel_eus:8.1",
									"cpe:/a:redhat:rhel_eus:8.1::appstream",
								},
								AdvisoryID: "RHSA-2020:9999",
							},
						},
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2018-17189", "Red Hat Enterprise Linux 8", "httpd:2.4::httpd"},
					value: advisory{
						Advisory: types.Advisory{
							FixedVersion: "0:2.4.37-30.module+el8.3.0+7001+0766b9e7",
						},
						Definitions: []Definition{
							{
								FixedVersion: "0:2.4.37-30.module+el8.3.0+7001+0766b9e7",
								AffectedCPEList: []string{
									"cpe:/a:redhat:enterprise_linux:8",
									"cpe:/a:redhat:enterprise_linux:8::appstream",
								},
								AdvisoryID: "RHSA-2020:4751",
							},
						},
					},
				},
			},
		},
		{
			name:            "no definitions dir",
			cacheDir:        filepath.Join("testdata", "no-definitions"),
			repositoryToCPE: `{"data": {}}`,
		},
		{
			name:            "repository-to-cpe is unavailable",
			cacheDir:        filepath.Join("testdata", "happy"),
			repositoryToCPE: ``,
			wantErr:         "returns 503",
		},
		{
			name:            "broken mapping",
			cacheDir:        filepath.Join("testdata", "happy"),
			repositoryToCPE: `{"data": "broken"}`,
			wantErr:         "JSON parse error",
		},
		{
			name:            "broken JSON",
			cacheDir:        filepath.Join("testdata", "sad"),
			repositoryToCPE: `{"data": {}}`,
			wantErr:         "failed to decode Red Hat OVAL JSON",
		},
		{
			name:            "no version dir",
			cacheDir:        filepath.Join("testdata", "no-version"),
			repositoryToCPE: `{"data": {}}`,
			wantErr:         "no such file or directory",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, db.Init(dir))

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.repositoryToCPE == "" {
					http.Error(w, "We'll be back soon", http.StatusServiceUnavailable)
					return
				}
				_, _ = fmt.Fprintln(w, tc.repositoryToCPE)
			}))
			defer ts.Close()

			vs := NewVulnSrc(WithMappingURL(ts.URL))
			err := vs.Update(tc.cacheDir)
			if tc.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tc.wantErr, tc.name)
				return
			}
			db.Close()

			assert.NoError(t, err)
			for _, w := range tc.wants {
				b, err := json.Marshal(w.value)
				require.NoError(t, err)

				dbtest.JSONEq(t, db.Path(dir), w.key, string(b))
			}
		})
	}
}

func TestVulnSrc_Get(t *testing.T) {
	type args struct {
		release      string
		pkgName      string
		repositories []string
	}
	tests := []struct {
		name         string
		args         args
		fixtureFiles []string
		want         []types.Advisory
		wantErr      string
	}{
		{
			name: "happy path",
			args: args{
				release:      "8",
				pkgName:      "bind",
				repositories: []string{"rhel-8-for-x86_64-baseos-rpms"},
			},
			fixtureFiles: []string{"testdata/fixtures/happy.yaml", "testdata/fixtures/cpe.yaml"},
			want: []types.Advisory{
				{
					VulnerabilityID: "CVE-2020-8624",
					VendorID:        "RHSA-2020:4500",
					FixedVersion:    "32:9.11.20-5.el8",
				},
			},
		},
		{
			name: "CPE doesn't match",
			args: args{
				release:      "8",
				pkgName:      "bind",
				repositories: []string{"3scale-amp-2-rpms-for-rhel-8-x86_64-debug-rpms"},
			},
			fixtureFiles: []string{"testdata/fixtures/happy.yaml", "testdata/fixtures/cpe.yaml"},
			want:         []types.Advisory(nil),
		},
		{
			//This should not be happened
			name: "unknown repository",
			args: args{
				release:      "8",
				pkgName:      "bind",
				repositories: []string{"unknown"},
			},
			fixtureFiles: []string{"testdata/fixtures/happy.yaml", "testdata/fixtures/cpe.yaml"},
			want: []types.Advisory{
				{
					VulnerabilityID: "CVE-2020-8624",
					FixedVersion:    "32:9.11.20-5.el8",
				},
			},
		},
		{
			name: "no advisory bucket",
			args: args{
				release:      "8",
				pkgName:      "bind",
				repositories: []string{"rhel-8-for-x86_64-baseos-rpms"},
			},
			fixtureFiles: []string{"testdata/fixtures/cpe.yaml"},
			want:         []types.Advisory(nil),
		},
		{
			name: "no CPE bucket",
			args: args{
				release:      "8",
				pkgName:      "bind",
				repositories: []string{"rhel-8-for-x86_64-baseos-rpms"},
			},
			fixtureFiles: []string{"testdata/fixtures/happy.yaml"},
			want: []types.Advisory{
				{
					VulnerabilityID: "CVE-2020-8624",
					FixedVersion:    "32:9.11.20-5.el8",
				},
			},
		},
		{
			name: "broken JSON",
			args: args{
				release:      "8",
				pkgName:      "bind",
				repositories: []string{"rhel-8-for-x86_64-baseos-rpms"},
			},
			fixtureFiles: []string{"testdata/fixtures/broken.yaml", "testdata/fixtures/cpe.yaml"},
			want:         []types.Advisory(nil),
			wantErr:      "failed to unmarshal advisory JSON",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := dbtest.InitDB(t, tt.fixtureFiles)
			require.NoError(t, db.Init(dir))
			defer db.Close()

			vs := NewVulnSrc()
			got, err := vs.Get(tt.args.release, tt.args.pkgName, tt.args.repositories)

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
