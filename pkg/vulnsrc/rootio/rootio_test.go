package rootio_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/rootio"
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
						"root.io alpine 3.18",
					},
					Value: types.DataSource{
						ID:     vulnerability.RootIO,
						Name:   "Root.io Security Patches (alpine)",
						URL:    "https://api.root.io/external/patch_feed",
						BaseID: vulnerability.Alpine,
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2023-38473",
						"root.io alpine 3.18",
						"rootio-curl",
					},
					Value: types.Advisory{
						VendorIDs:          []string{"ROOT-OS-ALPINE-318-CVE-2023-38473"},
						VulnerableVersions: []string{"<8.4.0-r0.root.io.1"},
						PatchedVersions:    []string{"8.4.0-r0.root.io.1"},
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2023-38473",
					},
					Value: map[string]any{},
				},
				{
					Key: []string{
						"data-source",
						"npm::Root.io Security Patches",
					},
					Value: types.DataSource{
						ID:   vulnerability.RootIO,
						Name: "Root.io Security Patches",
						URL:  "https://api.root.io/external/patch_feed",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2023-5678",
						"npm::Root.io Security Patches",
						"@rootio/axios",
					},
					Value: types.Advisory{
						VendorIDs:          []string{"ROOT-APP-NPM-CVE-2023-5678"},
						VulnerableVersions: []string{"<1.6.1"},
						PatchedVersions:    []string{"1.6.1"},
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2023-5678",
					},
					Value: map[string]any{},
				},
			},
			// Skipped entries (empty affected, no fixed) must not create buckets
			noBuckets: [][]string{
				{"advisory-detail", "CVE-2099-NOFIXED"},
				{"vulnerability-id", "CVE-2099-NOFIXED"},
				{"advisory-detail", "CVE-2099-EMPTY"},
				{"vulnerability-id", "CVE-2099-EMPTY"},
			},
		},
		{
			name:    "sad path - invalid JSON",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "json decode error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := rootio.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				NoBuckets:  tt.noBuckets,
				WantErr:    tt.wantErr,
			})
		})
	}
}

func TestVulnSrc_Get(t *testing.T) {
	type args struct {
		osVer   string
		pkgName string
	}
	tests := []struct {
		name     string
		baseOS   types.SourceID
		fixtures []string
		args     args
		want     []types.Advisory
		wantErr  string
	}{
		{
			name:   "only Root.io debian advisories",
			baseOS: vulnerability.Debian,
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer:   "11",
				pkgName: "openssl",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2023-0464",
					VulnerableVersions: []string{">=1.1.1, <1.1.1t"},
					PatchedVersions:    []string{"1.1.1t-1+deb11u2"},
					DataSource: &types.DataSource{
						ID:     vulnerability.RootIO,
						BaseID: vulnerability.Debian,
						Name:   "Root.io Security Patches (debian)",
						URL:    "https://api.root.io/external/patch_feed",
					},
				},
			},
		},
		{
			name:   "only Root.io debian advisories (with fixed version by Root.io and Debian)",
			baseOS: vulnerability.Debian,
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer:   "12",
				pkgName: "openssl",
			},
			want: []types.Advisory{
				{
					VulnerabilityID: "CVE-2024-13176",
					VulnerableVersions: []string{
						"<3.0.15-1~deb12u1.root.io.1",
						">3.0.15-1~deb12u1.root.io.1 <3.0.16-1~deb12u1",
					},
					PatchedVersions: []string{
						"3.0.15-1~deb12u1.root.io.1",
						"3.0.16-1~deb12u1",
					},
					DataSource: &types.DataSource{
						ID:     vulnerability.RootIO,
						BaseID: vulnerability.Debian,
						Name:   "Root.io Security Patches (debian)",
						URL:    "https://api.root.io/external/patch_feed",
					},
				},
			},
		},
		{
			name:   "only Root.io ubuntu advisories",
			baseOS: vulnerability.Ubuntu,
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer:   "20.04",
				pkgName: "nginx",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2023-44487",
					VulnerableVersions: []string{"<1.22.1-9+deb12u2.root.io.1"},
					PatchedVersions:    []string{"1.22.1-9+deb12u2.root.io.1"},
					DataSource: &types.DataSource{
						ID:     vulnerability.RootIO,
						BaseID: vulnerability.Ubuntu,
						Name:   "Root.io Security Patches (ubuntu)",
						URL:    "https://api.root.io/external/patch_feed",
					},
				},
			},
		},
		{
			name:   "only Root.io alpine advisories",
			baseOS: vulnerability.Alpine,
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer:   "3.19",
				pkgName: "less",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2024-32487",
					VulnerableVersions: []string{"<643-r00072"},
					PatchedVersions:    []string{"643-r00072"},
					DataSource: &types.DataSource{
						ID:     vulnerability.RootIO,
						BaseID: vulnerability.Alpine,
						Name:   "Root.io Security Patches (alpine)",
						URL:    "https://api.root.io/external/patch_feed",
					},
				},
			},
		},
		{
			name:   "Root.io and Debian have advisories",
			baseOS: vulnerability.Debian,
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer:   "11",
				pkgName: "pam",
			},
			want: []types.Advisory{
				{
					// Debian has no fixed version
					VulnerabilityID:    "CVE-2024-10041",
					VulnerableVersions: []string{"<1.5.2-6+deb12u1.root.io.3"},
					PatchedVersions:    []string{"1.5.2-6+deb12u1.root.io.3"},
					Severity:           types.SeverityMedium,
					DataSource: &types.DataSource{
						ID:     vulnerability.RootIO,
						BaseID: vulnerability.Debian,
						Name:   "Root.io Security Patches (debian)",
						URL:    "https://api.root.io/external/patch_feed",
					},
				},
				{
					// Debian has fixed version
					VulnerabilityID:    "CVE-2024-22365",
					VulnerableVersions: []string{"<1.5.2-6+deb12u1.root.io.3"},
					PatchedVersions:    []string{"1.5.2-6+deb12u1.root.io.3"},
					DataSource: &types.DataSource{
						ID:     vulnerability.RootIO,
						BaseID: vulnerability.Debian,
						Name:   "Root.io Security Patches (debian)",
						URL:    "https://api.root.io/external/patch_feed",
					},
				},
			},
		},
		{
			name:   "only debian advisories",
			baseOS: vulnerability.Debian,
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer:   "10",
				pkgName: "pam",
			},
			want: []types.Advisory{
				{
					VulnerabilityID: "CVE-2024-10041",
					Status:          types.StatusAffected,
					Severity:        types.SeverityLow,
					DataSource: &types.DataSource{
						ID:   vulnerability.Debian,
						Name: "Debian Security Tracker",
						URL:  "https://salsa.debian.org/security-tracker-team/security-tracker",
					},
				},
				{
					VulnerabilityID:    "CVE-2024-22365",
					VulnerableVersions: []string{"<1.5.2-6+deb12u2"},
					PatchedVersions:    []string{"1.5.2-6+deb12u2"},
					DataSource: &types.DataSource{
						ID:   vulnerability.Debian,
						Name: "Debian Security Tracker",
						URL:  "https://salsa.debian.org/security-tracker-team/security-tracker",
					},
				},
			},
		},
		{
			name:     "Root.io and Debian don't have advisories",
			baseOS:   vulnerability.Debian,
			fixtures: []string{"testdata/fixtures/broken.yaml"},
			args: args{
				osVer:   "12",
				pkgName: "openssl",
			},
		},
		{
			name:     "broken bucket",
			baseOS:   vulnerability.Debian,
			fixtures: []string{"testdata/fixtures/broken.yaml"},
			args: args{
				osVer:   "11",
				pkgName: "openssl",
			},
			wantErr: "failed to get advisories",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := rootio.NewVulnSrcGetter(tt.baseOS)
			vulnsrctest.TestGet(t, vs, vulnsrctest.TestGetArgs{
				Fixtures:   tt.fixtures,
				WantValues: tt.want,
				GetParams: db.GetParams{
					Release: tt.args.osVer,
					PkgName: tt.args.pkgName,
				},
				WantErr: tt.wantErr,
			})
		})
	}
}

func TestVulnSrc_Name(t *testing.T) {
	vs := rootio.NewVulnSrc()
	assert.Equal(t, vulnerability.RootIO, vs.Name())
}
