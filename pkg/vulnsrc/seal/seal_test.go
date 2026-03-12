package seal_test

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
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
						"seal Red Hat 6",
					},
					Value: types.DataSource{
						ID:     vulnerability.Seal,
						Name:   "Seal Security Database",
						URL:    "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
						BaseID: vulnerability.RedHat,
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2024-10524",
						"seal Red Hat 6",
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
						"seal debian",
					},
					Value: types.DataSource{
						ID:     vulnerability.Seal,
						Name:   "Seal Security Database",
						URL:    "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
						BaseID: vulnerability.Debian,
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2024-10524",
						"seal debian",
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
						"vulnerability-detail",
						"CVE-2024-10524",
						"seal",
					},
					Value: types.VulnerabilityDetail{
						LastModifiedDate: utils.MustTimeParse("2024-12-05T19:12:21.203740Z"),
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
						"seal alpine",
					},
					Value: types.DataSource{
						ID:     vulnerability.Seal,
						Name:   "Seal Security Database",
						URL:    "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
						BaseID: vulnerability.Alpine,
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2023-6992",
						"seal alpine",
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
				{
					Key: []string{
						"data-source",
						"seal maven::Seal Security Database",
					},
					Value: types.DataSource{
						ID:   vulnerability.Seal,
						Name: "Seal Security Database",
						URL:  "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2025-68161",
						"seal maven::Seal Security Database",
						"seal.sp1.org.apache.logging.log4j:log4j-core",
					},
					Value: types.Advisory{
						PatchedVersions: []string{
							"2.13.3+sp999",
						},
						VulnerableVersions: []string{
							">=2.13.3, <2.13.3+sp999",
						},
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2025-68161",
						"seal maven::Seal Security Database",
						"seal.sp3.org.apache.logging.log4j:log4j-core",
					},
					Value: types.Advisory{
						PatchedVersions: []string{
							"2.14.1+sp999",
						},
						VulnerableVersions: []string{
							">=2.14.1, <2.14.1+sp999",
						},
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2025-68161",
						"seal",
					},
					Value: types.VulnerabilityDetail{
						LastModifiedDate: utils.MustTimeParse("2026-01-14T16:19:33.150424Z"),
						PublishedDate:    utils.MustTimeParse("2025-12-18T00:00:00Z"),
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2025-68161",
					},
					Value: map[string]any{},
				},
				{
					Key: []string{
						"data-source",
						"seal pip::Seal Security Database",
					},
					Value: types.DataSource{
						ID:   vulnerability.Seal,
						Name: "Seal Security Database",
						URL:  "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2023-32681",
						"seal pip::Seal Security Database",
						"seal-requests",
					},
					Value: types.Advisory{
						PatchedVersions: []string{
							"2.14.2+sp999",
						},
						VulnerableVersions: []string{
							">=2.14.2+sp1, <2.14.2+sp999",
						},
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2023-32681",
						"seal",
					},
					Value: types.VulnerabilityDetail{
						LastModifiedDate: utils.MustTimeParse("2024-01-29T07:51:16.696541Z"),
						PublishedDate:    utils.MustTimeParse("2023-05-22T00:00:00Z"),
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2023-32681",
					},
					Value: map[string]any{},
				},
				{
					Key: []string{
						"data-source",
						"seal npm::Seal Security Database",
					},
					Value: types.DataSource{
						ID:   vulnerability.Seal,
						Name: "Seal Security Database",
						URL:  "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2025-69873",
						"seal npm::Seal Security Database",
						"@seal-security/ajv",
					},
					Value: types.Advisory{
						PatchedVersions: []string{
							"5.5.2-sp999",
						},
						VulnerableVersions: []string{
							">=5.5.2-sp1, <5.5.2-sp999",
						},
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2025-69873",
						"seal",
					},
					Value: types.VulnerabilityDetail{
						LastModifiedDate: utils.MustTimeParse("2026-03-05T00:19:07.862511Z"),
						PublishedDate:    utils.MustTimeParse("2026-02-11T00:00:00Z"),
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2025-69873",
					},
					Value: map[string]any{},
				},
				{
					Key: []string{
						"data-source",
						"seal go::Seal Security Database",
					},
					Value: types.DataSource{
						ID:   vulnerability.Seal,
						Name: "Seal Security Database",
						URL:  "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2025-22869",
						"seal go::Seal Security Database",
						"sealsecurity.io/golang.org/x/crypto",
					},
					Value: types.Advisory{
						PatchedVersions: []string{
							"0.26.0-sp2",
						},
						VulnerableVersions: []string{
							">=0.26.0-sp1, <0.26.0-sp2",
						},
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2025-22869",
						"seal",
					},
					Value: types.VulnerabilityDetail{
						LastModifiedDate: utils.MustTimeParse("2025-05-15T11:43:10.691190Z"),
						PublishedDate:    utils.MustTimeParse("2025-02-26T00:00:00Z"),
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2025-22869",
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
		baseOS   ecosystem.Type
		fixtures []string
		args     args
		want     []types.Advisory
		wantErr  string
	}{
		{
			name:   "Seal debian advisories",
			baseOS: ecosystem.Debian,
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				pkgName: "seal-wget",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2024-10524",
					VulnerableVersions: []string{">=1.21-1+deb11u1, <1.21-1+deb11u1+sp999"},
					PatchedVersions:    []string{"1.21-1+deb11u1+sp999"},
					DataSource: &types.DataSource{
						ID:     vulnerability.Seal,
						BaseID: vulnerability.Debian,
						Name:   "Seal Security Database",
						URL:    "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
					},
				},
				{
					VulnerabilityID:    "CVE-2024-10524",
					VulnerableVersions: []string{">=1.22-2+deb12u1, <1.22-2+deb12u1+sp999"},
					PatchedVersions:    []string{"1.22-2+deb12u1+sp999"},
					DataSource: &types.DataSource{
						ID:     vulnerability.Seal,
						BaseID: vulnerability.Debian,
						Name:   "Seal Security Database",
						URL:    "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
					},
				},
			},
		},
		{
			name:   "Seal alpine advisories",
			baseOS: ecosystem.Alpine,
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				pkgName: "seal-zlib",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2023-6992",
					VulnerableVersions: []string{">=1.2.8-r2, <1.2.8-r25341999"},
					PatchedVersions:    []string{"1.2.8-r25341999"},
					DataSource: &types.DataSource{
						ID:     vulnerability.Seal,
						BaseID: vulnerability.Alpine,
						Name:   "Seal Security Database",
						URL:    "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
					},
				},
			},
		},
		{
			name:   "Seal redhat advisories",
			baseOS: ecosystem.RedHat,
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer:   "6",
				pkgName: "seal-wget",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2024-10524",
					VulnerableVersions: []string{">=1.12-10.el6, <1.12-10.el6+sp999"},
					PatchedVersions:    []string{"1.12-10.el6+sp999"},
					DataSource: &types.DataSource{
						ID:     vulnerability.Seal,
						BaseID: vulnerability.RedHat,
						Name:   "Seal Security Database",
						URL:    "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
					},
				},
			},
		},
		{
			name:   "no advisories",
			baseOS: ecosystem.Debian,
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				osVer:   "10",
				pkgName: "seal-unknown",
			},
		},
		{
			name:     "broken Seal bucket",
			baseOS:   ecosystem.Debian,
			fixtures: []string{"testdata/fixtures/broken.yaml"},
			args: args{
				pkgName: "seal-wget",
			},
			wantErr: "failed to get advisories for base OS",
		},
		{
			name:     "broken orders for VulnerableVersions and PatchedVersions",
			baseOS:   ecosystem.Debian,
			fixtures: []string{"testdata/fixtures/broken-vers-order.yaml"},
			args: args{
				pkgName: "seal-wget",
			},
			wantErr: "failed to split advisories by ranges: vulnerable version range should contain the patched version",
		},
		{
			name:   "Seal maven advisories",
			baseOS: ecosystem.Maven,
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				pkgName: "seal.sp1.org.apache.logging.log4j:log4j-core",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2025-68161",
					VulnerableVersions: []string{">=2.13.3, <2.13.3+sp999"},
					PatchedVersions:    []string{"2.13.3+sp999"},
					DataSource: &types.DataSource{
						ID:   vulnerability.Seal,
						Name: "Seal Security Database",
						URL:  "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
					},
				},
			},
		},
		{
			name:   "Seal pip advisories",
			baseOS: ecosystem.Pip,
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				pkgName: "seal-requests",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2023-32681",
					VulnerableVersions: []string{">=2.14.2+sp1, <2.14.2+sp999"},
					PatchedVersions:    []string{"2.14.2+sp999"},
					DataSource: &types.DataSource{
						ID:   vulnerability.Seal,
						Name: "Seal Security Database",
						URL:  "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
					},
				},
			},
		},
		{
			name:   "Seal npm advisories",
			baseOS: ecosystem.Npm,
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				pkgName: "@seal-security/ajv",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2025-69873",
					VulnerableVersions: []string{">=5.5.2-sp1, <5.5.2-sp999"},
					PatchedVersions:    []string{"5.5.2-sp999"},
					DataSource: &types.DataSource{
						ID:   vulnerability.Seal,
						Name: "Seal Security Database",
						URL:  "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
					},
				},
			},
		},
		{
			name:   "Seal go advisories",
			baseOS: ecosystem.Go,
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			args: args{
				pkgName: "sealsecurity.io/golang.org/x/crypto",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2025-22869",
					VulnerableVersions: []string{">=0.26.0-sp1, <0.26.0-sp2"},
					PatchedVersions:    []string{"0.26.0-sp2"},
					DataSource: &types.DataSource{
						ID:   vulnerability.Seal,
						Name: "Seal Security Database",
						URL:  "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
					},
				},
			},
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
