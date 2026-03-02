package rapidfort_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/rapidfort"
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
						"rapidfort ubuntu 20.04",
					},
					Value: types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "ubuntu",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2020-8169",
						"rapidfort ubuntu 20.04",
						"curl",
					},
					Value: types.Advisory{
						PatchedVersions:    []string{"7.68.0-1ubuntu2.1"},
						VulnerableVersions: []string{">= 7.68.0, < 7.68.0-1ubuntu2.1"},
						Severity:           types.SeverityHigh,
					},
				},
				{
					// Open vulnerability: no patched version
					Key: []string{
						"advisory-detail",
						"CVE-2021-22876",
						"rapidfort ubuntu 20.04",
						"curl",
					},
					Value: types.Advisory{
						VulnerableVersions: []string{">=7.68.0"},
						Severity:           types.SeverityMedium,
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2020-8169",
					},
					Value: map[string]any{},
				},
				{
					Key: []string{
						"data-source",
						"rapidfort debian 12",
					},
					Value: types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "debian",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2024-5535",
						"rapidfort debian 12",
						"openssl",
					},
					Value: types.Advisory{
						PatchedVersions:    []string{"3.0.14-1~deb12u2"},
						VulnerableVersions: []string{">= 3.0.0, < 3.0.14-1~deb12u2"},
						Severity:           types.SeverityCritical,
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2024-5535",
					},
					Value: map[string]any{},
				},
			},
		},
		{
			name: "empty dir - no advisories",
			dir:  filepath.Join("testdata", "empty"),
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := rapidfort.NewVulnSrc()
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
	tests := []struct {
		name    string
		baseOS  string
		osVer   string
		pkgName string
		fixtures []string
		want    []types.Advisory
		wantErr string
	}{
		{
			name:    "ubuntu advisory found",
			baseOS:  "ubuntu",
			osVer:   "20.04",
			pkgName: "curl",
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2020-8169",
					VulnerableVersions: []string{">= 7.68.0, < 7.68.0-1ubuntu2.1"},
					PatchedVersions:    []string{"7.68.0-1ubuntu2.1"},
					Severity:           types.SeverityHigh,
					DataSource: &types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "ubuntu",
					},
				},
			},
		},
		{
			name:    "debian advisory found",
			baseOS:  "debian",
			osVer:   "12",
			pkgName: "openssl",
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2024-5535",
					VulnerableVersions: []string{">= 3.0.0, < 3.0.14-1~deb12u2"},
					PatchedVersions:    []string{"3.0.14-1~deb12u2"},
					Severity:           types.SeverityCritical,
					DataSource: &types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "debian",
					},
				},
			},
		},
		{
			name:    "no advisory for package",
			baseOS:  "ubuntu",
			osVer:   "22.04",
			pkgName: "curl",
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := rapidfort.NewVulnSrcGetter(tt.baseOS)
			vulnsrctest.TestGet(t, vs, vulnsrctest.TestGetArgs{
				Fixtures:   tt.fixtures,
				WantValues: tt.want,
				GetParams: db.GetParams{
					Release: tt.osVer,
					PkgName: tt.pkgName,
				},
				WantErr: tt.wantErr,
			})
		})
	}
}

func TestVulnSrc_Name(t *testing.T) {
	vs := rapidfort.NewVulnSrc()
	assert.Equal(t, vulnerability.RapidFort, vs.Name())
}
