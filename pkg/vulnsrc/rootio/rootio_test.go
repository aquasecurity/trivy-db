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
						"root.io debian 12",
					},
					Value: types.DataSource{
						ID:     vulnerability.RootIO,
						Name:   "Root.io Security Patches (debian)",
						URL:    "https://api.root.io/external/patch_feed",
						BaseID: vulnerability.Debian,
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2025-29088",
						"root.io debian 12",
						"sqlite3",
					},
					Value: types.Advisory{
						VulnerableVersions: []string{"<3.40.1-2+deb12u1.root.io.2"},
						PatchedVersions:    []string{"3.40.1-2+deb12u1.root.io.2"},
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2025-29088",
					},
					Value: map[string]any{},
				},
				{
					Key: []string{
						"data-source",
						"root.io alpine 3.17",
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
						"CVE-2023-46853",
						"root.io alpine 3.17",
						"memcached",
					},
					Value: types.Advisory{
						VulnerableVersions: []string{"<1.6.17-r00071"},
						PatchedVersions:    []string{"1.6.17-r00071"},
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2023-46853",
					},
					Value: map[string]any{},
				},
				{
					Key: []string{
						"data-source",
						"root.io ubuntu 22.04",
					},
					Value: types.DataSource{
						ID:     vulnerability.RootIO,
						Name:   "Root.io Security Patches (ubuntu)",
						URL:    "https://api.root.io/external/patch_feed",
						BaseID: vulnerability.Ubuntu,
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2023-29383",
						"root.io ubuntu 22.04",
						"shadow",
					},
					Value: types.Advisory{
						VulnerableVersions: []string{"<1:4.8.1-2ubuntu2.2.root.io.2"},
						PatchedVersions:    []string{"1:4.8.1-2ubuntu2.2.root.io.2"},
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2023-29383",
					},
					Value: map[string]any{},
				},
			},
		},
		{
			name: "happy path with unsupported OS",
			dir:  filepath.Join("testdata", "unsupported-os"),
			noBuckets: [][]string{
				{"advisory-detail"},
				{"vulnerability-id"},
				{"vulnerability-detail"},
			},
		},
		{
			name:    "sad path - invalid JSON",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "json decode error",
		},
		{
			name: "happy path with language packages",
			dir:  filepath.Join("testdata", "language-packages"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{
						"data-source",
						"root.io pip",
					},
					Value: types.DataSource{
						ID:   vulnerability.RootIO,
						Name: "Root.io Security Patches (pip)",
						URL:  "https://api.root.io/external/patch_feed",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2024-1234",
						"root.io pip",
						"django",
					},
					Value: types.Advisory{
						VulnerableVersions: []string{"<4.0.2"},
						PatchedVersions:    []string{"4.0.2.root.io"},
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2024-1234",
					},
					Value: map[string]any{},
				},
				{
					Key: []string{
						"data-source",
						"root.io npm",
					},
					Value: types.DataSource{
						ID:   vulnerability.RootIO,
						Name: "Root.io Security Patches (npm)",
						URL:  "https://api.root.io/external/patch_feed",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2024-5678",
						"root.io npm",
						"express",
					},
					Value: types.Advisory{
						VulnerableVersions: []string{"<4.18.0"},
						PatchedVersions:    []string{"4.18.0.root.io"},
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2024-5678",
					},
					Value: map[string]any{},
				},
			},
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

func TestVulnSrcGetter_Get_OS(t *testing.T) {
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

func TestVulnSrc_Update_Comprehensive(t *testing.T) {
	tests := []struct {
		name       string
		dir        string
		wantValues []vulnsrctest.WantValues
		wantErr    string
	}{
		{
			name: "comprehensive OS and language packages",
			dir:  filepath.Join("testdata", "comprehensive"),
			wantValues: []vulnsrctest.WantValues{
				// OS package advisories
				{
					Key: []string{
						"advisory-detail",
						"CVE-2024-OS-001",
						"root.io debian 12",
						"nginx",
					},
					Value: types.Advisory{
						VulnerableVersions: []string{"<1.24.0"},
						PatchedVersions:    []string{"1.24.0.root.io"},
					},
				},
				// Python packages
				{
					Key: []string{
						"advisory-detail",
						"CVE-2024-PY-001",
						"root.io pip",
						"requests",
					},
					Value: types.Advisory{
						VulnerableVersions: []string{"<2.31.0"},
						PatchedVersions:    []string{"2.31.0.root.io"},
					},
				},
				// Go packages
				{
					Key: []string{
						"advisory-detail",
						"CVE-2024-GO-001",
						"root.io go",
						"github.com/gin-gonic/gin",
					},
					Value: types.Advisory{
						VulnerableVersions: []string{"<1.9.1"},
						PatchedVersions:    []string{"1.9.1.root.io"},
					},
				},
				// Maven packages
				{
					Key: []string{
						"advisory-detail",
						"CVE-2024-JAVA-001",
						"root.io maven",
						"org.springframework.boot:spring-boot",
					},
					Value: types.Advisory{
						VulnerableVersions: []string{"<3.2.0"},
						PatchedVersions:    []string{"3.2.0.root.io"},
					},
				},
			},
		},
		{
			name: "mixed valid and invalid ecosystems",
			dir:  filepath.Join("testdata", "mixed-ecosystems"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{
						"advisory-detail",
						"CVE-2024-VALID-001",
						"root.io npm",
						"react",
					},
					Value: types.Advisory{
						VulnerableVersions: []string{"<18.2.0"},
						PatchedVersions:    []string{"18.2.0.root.io"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := rootio.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
			})
		})
	}
}

func TestVulnSrcGetter_Get_Ecosystem(t *testing.T) {
	tests := []struct {
		name      string
		ecosystem types.Ecosystem
		fixtures  []string
		pkgName   string
		want      []types.Advisory
		wantErr   string
	}{
		{
			name:      "Python package with rootio patches",
			ecosystem: vulnerability.Pip,
			fixtures: []string{
				"testdata/fixtures/language-packages.yaml",
			},
			pkgName: "django",
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2024-1234",
					VulnerableVersions: []string{"<4.0.2"},
					PatchedVersions:    []string{"4.0.2.root.io"},
					DataSource: &types.DataSource{
						ID:   vulnerability.RootIO,
						Name: "Root.io Security Patches (pip)",
						URL:  "https://api.root.io/external/patch_feed",
					},
				},
			},
		},
		{
			name:      "Node.js package with rootio patches",
			ecosystem: vulnerability.Npm,
			fixtures: []string{
				"testdata/fixtures/language-packages.yaml",
			},
			pkgName: "express",
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2024-5678",
					VulnerableVersions: []string{"<4.18.0"},
					PatchedVersions:    []string{"4.18.0.root.io"},
					DataSource: &types.DataSource{
						ID:   vulnerability.RootIO,
						Name: "Root.io Security Patches (npm)",
						URL:  "https://api.root.io/external/patch_feed",
					},
				},
			},
		},
		{
			name:      "Ruby package with rootio patches",
			ecosystem: vulnerability.RubyGems,
			fixtures: []string{
				"testdata/fixtures/language-packages.yaml",
			},
			pkgName: "rails",
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2024-9999",
					VulnerableVersions: []string{"<7.0.0"},
					PatchedVersions:    []string{"7.0.0.root.io"},
					DataSource: &types.DataSource{
						ID:   vulnerability.RootIO,
						Name: "Root.io Security Patches (rubygems)",
						URL:  "https://api.root.io/external/patch_feed",
					},
				},
			},
		},
		{
			name:      "Package not found",
			ecosystem: vulnerability.Pip,
			fixtures: []string{
				"testdata/fixtures/language-packages.yaml",
			},
			pkgName: "nonexistent",
			want:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getter := rootio.NewEcosystemVulnSrcGetter(tt.ecosystem)
			vulnsrctest.TestGet(t, getter, vulnsrctest.TestGetArgs{
				Fixtures:   tt.fixtures,
				WantValues: tt.want,
				GetParams: db.GetParams{
					PkgName: tt.pkgName,
				},
				WantErr: tt.wantErr,
			})
		})
	}
}

func TestVulnSrcGetter_Get_Comprehensive(t *testing.T) {
	tests := []struct {
		name     string
		getterFn func() db.Getter
		fixtures []string
		params   db.GetParams
		want     []types.Advisory
	}{
		{
			name: "OS package with multiple vulnerabilities",
			getterFn: func() db.Getter {
				return rootio.NewVulnSrcGetter(vulnerability.Debian)
			},
			fixtures: []string{
				"testdata/fixtures/comprehensive-os.yaml",
			},
			params: db.GetParams{
				Release: "12",
				PkgName: "postgresql",
				Arch:    "",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2024-DB-001",
					VulnerableVersions: []string{"<15.4"},
					PatchedVersions:    []string{"15.4.root.io"},
					DataSource: &types.DataSource{
						ID:     vulnerability.RootIO,
						Name:   "Root.io Security Patches (debian)",
						URL:    "https://api.root.io/external/patch_feed",
						BaseID: vulnerability.Debian,
					},
				},
				{
					VulnerabilityID:    "CVE-2024-DB-002",
					VulnerableVersions: []string{"<15.5"},
					PatchedVersions:    []string{"15.5.root.io"},
					DataSource: &types.DataSource{
						ID:     vulnerability.RootIO,
						Name:   "Root.io Security Patches (debian)",
						URL:    "https://api.root.io/external/patch_feed",
						BaseID: vulnerability.Debian,
					},
				},
			},
		},
		{
			name: "Language package with complex version ranges",
			getterFn: func() db.Getter {
				return rootio.NewEcosystemVulnSrcGetter(vulnerability.Pip)
			},
			fixtures: []string{
				"testdata/fixtures/comprehensive-lang.yaml",
			},
			params: db.GetParams{
				PkgName: "cryptography",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2024-CRYPTO-001",
					VulnerableVersions: []string{">=41.0.0,<41.0.5", ">=40.0.0,<40.0.2"},
					PatchedVersions:    []string{"41.0.5.root.io", "40.0.2.root.io"},
					DataSource: &types.DataSource{
						ID:   vulnerability.RootIO,
						Name: "Root.io Security Patches (pip)",
						URL:  "https://api.root.io/external/patch_feed",
					},
				},
			},
		},
		{
			name: "Go module with nested path",
			getterFn: func() db.Getter {
				return rootio.NewEcosystemVulnSrcGetter(vulnerability.Go)
			},
			fixtures: []string{
				"testdata/fixtures/comprehensive-lang.yaml",
			},
			params: db.GetParams{
				PkgName: "golang.org/x/crypto/ssh",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2024-SSH-001",
					VulnerableVersions: []string{"<0.17.0"},
					PatchedVersions:    []string{"0.17.0.root.io"},
					DataSource: &types.DataSource{
						ID:   vulnerability.RootIO,
						Name: "Root.io Security Patches (go)",
						URL:  "https://api.root.io/external/patch_feed",
					},
				},
			},
		},
		{
			name: "Multiple ecosystems same package name",
			getterFn: func() db.Getter {
				return rootio.NewEcosystemVulnSrcGetter(vulnerability.Npm)
			},
			fixtures: []string{
				"testdata/fixtures/multi-ecosystem.yaml",
			},
			params: db.GetParams{
				PkgName: "lodash",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2024-NPM-LODASH",
					VulnerableVersions: []string{"<4.17.21"},
					PatchedVersions:    []string{"4.17.21.root.io"},
					DataSource: &types.DataSource{
						ID:   vulnerability.RootIO,
						Name: "Root.io Security Patches (npm)",
						URL:  "https://api.root.io/external/patch_feed",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getter := tt.getterFn()
			vulnsrctest.TestGet(t, getter, vulnsrctest.TestGetArgs{
				Fixtures:   tt.fixtures,
				WantValues: tt.want,
				GetParams:  tt.params,
			})
		})
	}
}
