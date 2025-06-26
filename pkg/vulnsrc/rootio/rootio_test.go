package rootio_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/rootio"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
)

func TestVulnSrc_Update(t *testing.T) {
	tests := []struct {
		name       string
		baseOS     types.SourceID
		dir        string
		wantValues []vulnsrctest.WantValues
		wantErr    string
	}{
		{
			name:   "happy path debian",
			baseOS: vulnerability.Debian,
			dir:    filepath.Join("testdata", "happy"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{
						"data-source",
						"root.io debian 11",
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
						"CVE-2023-0464",
						"root.io debian 11",
						"openssl",
					},
					Value: types.Advisory{
						VulnerableVersions: []string{">=1.1.1, <1.1.1t"},
						PatchedVersions:    []string{"1.1.1t-1+deb11u2"},
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2023-28321",
						"root.io debian 11",
						"curl",
					},
					Value: types.Advisory{
						VulnerableVersions: []string{">=7.74.0, <7.88.1"},
						PatchedVersions:    []string{"7.74.0-1.3+deb11u7"},
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2023-0464",
					},
					Value: map[string]any{},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2023-28321",
					},
					Value: map[string]any{},
				},
			},
		},
		{
			name:   "happy path ubuntu",
			baseOS: vulnerability.Ubuntu,
			dir:    filepath.Join("testdata", "happy"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{
						"data-source",
						"root.io ubuntu 20.04",
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
						"CVE-2023-44487",
						"root.io ubuntu 20.04",
						"nginx",
					},
					Value: types.Advisory{
						VulnerableVersions: []string{">=1.18.0, <1.18.0-6ubuntu14.4"},
						PatchedVersions:    []string{"1.18.0-6ubuntu14.4"},
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2023-44487",
					},
					Value: map[string]any{},
				},
			},
		},
		{
			name:   "happy path alpine",
			baseOS: vulnerability.Alpine,
			dir:    filepath.Join("testdata", "happy"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{
						"data-source",
						"root.io alpine 3.20",
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
						"CVE-2023-42363",
						"root.io alpine 3.20",
						"busybox",
					},
					Value: types.Advisory{
						VulnerableVersions: []string{">=1.36.1, <1.36.1-r5"},
						PatchedVersions:    []string{"1.36.1-r5"},
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2023-42363",
					},
					Value: map[string]any{},
				},
			},
		},
		{
			name:    "sad path - invalid JSON",
			baseOS:  vulnerability.Debian,
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "json decode error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := rootio.NewVulnSrc(tt.baseOS)
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
			name:     "debian",
			baseOS:   vulnerability.Debian,
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			args: args{
				osVer:   "11",
				pkgName: "openssl",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2023-0464",
					VulnerableVersions: []string{">=1.1.1, <1.1.1t"},
					PatchedVersions:    []string{"1.1.1t-1+deb11u2"},
				},
			},
		},
		{
			name:     "ubuntu",
			baseOS:   vulnerability.Ubuntu,
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			args: args{
				osVer:   "20.04",
				pkgName: "nginx",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2023-44487",
					VulnerableVersions: []string{">=1.18.0, <1.18.0-6ubuntu14.4"},
					PatchedVersions:    []string{"1.18.0-6ubuntu14.4"},
				},
			},
		},
		{
			name:     "alpine",
			baseOS:   vulnerability.Alpine,
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			args: args{
				osVer:   "3.20",
				pkgName: "busybox",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2023-42363",
					VulnerableVersions: []string{">=1.36.1, <1.36.1-r5"},
					PatchedVersions:    []string{"1.36.1-r5"},
				},
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
			vs := rootio.NewVulnSrc(tt.baseOS)
			vulnsrctest.TestGet(t, vs, vulnsrctest.TestGetArgs{
				Fixtures:   tt.fixtures,
				WantValues: tt.want,
				Release:    tt.args.osVer,
				PkgName:    tt.args.pkgName,
				WantErr:    tt.wantErr,
			})
		})
	}
}

func TestVulnSrc_Name(t *testing.T) {
	vs := rootio.NewVulnSrc(vulnerability.Debian)
	assert.Equal(t, vulnerability.RootIO, vs.Name())
}
