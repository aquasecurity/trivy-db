package seal_test

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/seal"
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
						"seal redhat 9",
					},
					Value: types.DataSource{
						ID:     vulnerability.Seal,
						Name:   "Seal Security Database",
						URL:    "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
						BaseID: "redhat",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2024-10524",
						"seal redhat 9",
						"seal-wget",
					},
					Value: types.Advisory{
						PatchedVersions: []string{
							"1.12-10.el6+sp999",
						},
						VulnerableVersions: []string{
							">=1.12-10.el6, <1.12-10.el6+sp999",
						},
					},
				},
				{
					Key: []string{
						"data-source",
						"seal debian 12",
					},
					Value: types.DataSource{
						ID:     vulnerability.Seal,
						Name:   "Seal Security Database",
						URL:    "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
						BaseID: "debian",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2024-10524",
						"seal debian 12",
						"seal-wget",
					},
					Value: types.Advisory{
						PatchedVersions: []string{
							"1.21-1+deb11u1+sp999",
						},
						VulnerableVersions: []string{
							">=1.21-1+deb11u1, <1.21-1+deb11u1+sp999",
						},
					},
				},
				{
					Key: []string{
						"data-source",
						"seal ubuntu 22.04",
					},
					Value: types.DataSource{
						ID:     vulnerability.Seal,
						Name:   "Seal Security Database",
						URL:    "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
						BaseID: "ubuntu",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2024-10524",
						"seal ubuntu 22.04",
						"seal-wget",
					},
					Value: types.Advisory{
						PatchedVersions: []string{
							"1.21-1+deb11u1+sp999",
						},
						VulnerableVersions: []string{
							">=1.21-1+deb11u1, <1.21-1+deb11u1+sp999",
						},
					},
				},
				{
					Key: []string{
						"data-source",
						"seal oracle-linux 8",
					},
					Value: types.DataSource{
						ID:     vulnerability.Seal,
						Name:   "Seal Security Database",
						URL:    "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
						BaseID: "oracle-oval",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2024-10524",
						"seal oracle-linux 8",
						"seal-wget",
					},
					Value: types.Advisory{
						PatchedVersions: []string{
							"1.12-10.el6+sp999",
						},
						VulnerableVersions: []string{
							">=1.12-10.el6, <1.12-10.el6+sp999",
						},
					},
				},
				{
					Key: []string{
						"data-source",
						"seal centos 8",
					},
					Value: types.DataSource{
						ID:     vulnerability.Seal,
						Name:   "Seal Security Database",
						URL:    "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
						BaseID: "centos",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2024-10524",
						"seal centos 8",
						"seal-wget",
					},
					Value: types.Advisory{
						PatchedVersions: []string{
							"1.12-10.el6+sp999",
						},
						VulnerableVersions: []string{
							">=1.12-10.el6, <1.12-10.el6+sp999",
						},
					},
				},
				{
					Key: []string{
						"data-source",
						"seal cbl-mariner 2.0",
					},
					Value: types.DataSource{
						ID:     vulnerability.Seal,
						Name:   "Seal Security Database",
						URL:    "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
						BaseID: "cbl-mariner",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2024-10524",
						"seal cbl-mariner 2.0",
						"seal-wget",
					},
					Value: types.Advisory{
						PatchedVersions: []string{
							"1.12-10.el6+sp999",
						},
						VulnerableVersions: []string{
							">=1.12-10.el6, <1.12-10.el6+sp999",
						},
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2024-10524",
						"seal",
					},
					Value: types.VulnerabilityDetail{
						LastModifiedDate: utils.MustTimeParse("2024-12-29T13:51:52.847037Z"),
						PublishedDate:    utils.MustTimeParse("2024-11-19T00:00:00Z"),
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2024-10524",
					},
					Value: map[string]any{},
				},
				{
					Key: []string{
						"data-source",
						"seal alpine 3.21",
					},
					Value: types.DataSource{
						ID:     vulnerability.Seal,
						Name:   "Seal Security Database",
						URL:    "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
						BaseID: "alpine",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2023-6992",
						"seal alpine 3.21",
						"seal-zlib",
					},
					Value: types.Advisory{
						PatchedVersions: []string{
							"1.2.8-r25341999",
						},
						VulnerableVersions: []string{
							">=1.2.8-r2, <1.2.8-r25341999",
						},
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2023-6992",
						"seal",
					},
					Value: types.VulnerabilityDetail{
						LastModifiedDate: utils.MustTimeParse("2025-02-16T14:14:54.473509Z"),
						PublishedDate:    utils.MustTimeParse("2024-01-04T00:00:00Z"),
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2023-6992",
					},
					Value: map[string]any{},
				},
			},
		},
		{
			name:    "sad path (dir doesn't exist)",
			dir:     filepath.Join("testdata", "badPath"),
			wantErr: "no such file or directory",
		},
		{
			name:    "sad path (failed to decode)",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "json decode error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := seal.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
				NoBuckets:  tt.noBuckets,
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
			name:   "only Seal debian advisories",
			baseOS: vulnerability.Debian,
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer:   "12",
				pkgName: "seal-wget",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2024-10524",
					VulnerableVersions: []string{">=1.21-1+deb11u1, <1.21-1+deb11u1+sp999"},
					PatchedVersions:    []string{"1.21-1+deb11u1+sp999"},
					DataSource: &types.DataSource{
						ID:   vulnerability.Seal,
						Name: "Seal Security Database",
						URL:  "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
					},
				},
			},
		},
		{
			name:   "only Seal ubuntu advisories",
			baseOS: vulnerability.Ubuntu,
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer:   "22.04",
				pkgName: "seal-wget",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2024-10524",
					VulnerableVersions: []string{">=1.21-1+deb11u1, <1.21-1+deb11u1+sp999"},
					PatchedVersions:    []string{"1.21-1+deb11u1+sp999"},
					DataSource: &types.DataSource{
						ID:   vulnerability.Seal,
						Name: "Seal Security Database",
						URL:  "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
					},
				},
			},
		},
		{
			name:   "only Seal alpine advisories",
			baseOS: vulnerability.Alpine,
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer:   "3.21",
				pkgName: "seal-zlib",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2023-6992",
					VulnerableVersions: []string{">=1.2.8-r2, <1.2.8-r2+sp999"},
					PatchedVersions:    []string{"1.2.8-r2+sp999"},
					DataSource: &types.DataSource{
						ID:   vulnerability.Seal,
						Name: "Seal Security Database",
						URL:  "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
					},
				},
			},
		},
		{
			name:   "only Seal redhat advisories",
			baseOS: vulnerability.RedHat,
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer:   "9",
				pkgName: "seal-wget",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2024-10524",
					VulnerableVersions: []string{">=1.12-10.el6, <1.12-10.el6+sp999"},
					PatchedVersions:    []string{"1.12-10.el6+sp999"},
					DataSource: &types.DataSource{
						ID:   vulnerability.Seal,
						Name: "Seal Security Database",
						URL:  "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
					},
				},
			},
		},
		{
			name:   "only Seal centos advisories",
			baseOS: vulnerability.CentOS,
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer:   "8",
				pkgName: "seal-wget",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2024-10524",
					VulnerableVersions: []string{">=1.12-10.el6, <1.12-10.el6+sp999"},
					PatchedVersions:    []string{"1.12-10.el6+sp999"},
					DataSource: &types.DataSource{
						ID:   vulnerability.Seal,
						Name: "Seal Security Database",
						URL:  "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
					},
				},
			},
		},
		{
			name:   "only Seal oracle linux advisories",
			baseOS: types.SourceID("oracle-linux"),
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer:   "8",
				pkgName: "seal-wget",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2024-10524",
					VulnerableVersions: []string{">=1.12-10.el6, <1.12-10.el6+sp999"},
					PatchedVersions:    []string{"1.12-10.el6+sp999"},
					DataSource: &types.DataSource{
						ID:   vulnerability.Seal,
						Name: "Seal Security Database",
						URL:  "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
					},
				},
			},
		},
		{
			name:   "only Seal cbl-mariner advisories",
			baseOS: vulnerability.CBLMariner,
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer:   "2.0",
				pkgName: "seal-wget",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2024-10524",
					VulnerableVersions: []string{">=1.12-10.el6, <1.12-10.el6+sp999"},
					PatchedVersions:    []string{"1.12-10.el6+sp999"},
					DataSource: &types.DataSource{
						ID:   vulnerability.Seal,
						Name: "Seal Security Database",
						URL:  "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
					},
				},
			},
		},
		{
			name:   "no advisories",
			baseOS: vulnerability.Debian,
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer:   "10",
				pkgName: "seal-wget",
			},
		},
		{
			name:     "broken Seal bucket",
			baseOS:   vulnerability.Debian,
			fixtures: []string{"testdata/fixtures/broken.yaml"},
			args: args{
				osVer:   "12",
				pkgName: "seal-wget",
			},
			wantErr: "failed to get advisories for base OS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := seal.NewVulnSrcGetter(tt.baseOS)
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
