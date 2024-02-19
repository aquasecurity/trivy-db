package debian_test

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/debian"
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
						"debian 9",
					},
					Value: types.DataSource{
						ID:   vulnerability.Debian,
						Name: "Debian Security Tracker",
						URL:  "https://salsa.debian.org/security-tracker-team/security-tracker",
					},
				},
				// Ref. https://security-tracker.debian.org/tracker/CVE-2021-33560
				{
					Key: []string{
						"advisory-detail",
						"CVE-2021-33560",
						"debian 9",
						"libgcrypt20",
					},
					Value: &types.Advisory{
						VendorIDs:    []string{"DLA-2691-1"},
						FixedVersion: "1.7.6-2+deb9u4",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2021-33560",
						"debian 10",
						"libgcrypt20",
					},
					Value: &types.Advisory{
						FixedVersion: "1.8.4-5+deb10u1",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2021-33560",
						"debian 11",
						"libgcrypt20",
					},
					Value: &types.Advisory{
						FixedVersion: "1.8.7-6",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2021-29629",
						"debian 10",
						"dacs",
					},
					Value: &types.Advisory{
						Severity: types.SeverityLow,
						Status:   types.StatusWillNotFix,
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"DSA-3714-1",
						"debian 8",
						"akonadi",
					},
					Value: &types.Advisory{
						VendorIDs:    []string{"DSA-3714-1"},
						FixedVersion: "1.13.0-2+deb8u2",
					},
				},
				{
					// wrong no-dsa
					Key: []string{
						"advisory-detail",
						"CVE-2020-8631",
						"debian 11",
						"cloud-init",
					},
					Value: &types.Advisory{
						FixedVersion: "19.4-2",
					},
				},
				{
					// Fix version not released yet
					Key: []string{
						"advisory-detail",
						"CVE-2023-5981",
						"debian 11",
						"gnutls28",
					},
					Value: &types.Advisory{
						Status: types.StatusAffected,
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2021-33560",
						string(vulnerability.Debian),
					},
					Value: types.VulnerabilityDetail{
						Title: "Libgcrypt before 1.8.8 and 1.9.x before 1.9.3 mishandles ElGamal encry ...",
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2021-29629",
						string(vulnerability.Debian),
					},
					Value: types.VulnerabilityDetail{
						Title: "In FreeBSD 13.0-STABLE before n245765-bec0d2c9c841, 12.2-STABLE before ...",
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"DSA-3714-1",
						string(vulnerability.Debian),
					},
					Value: types.VulnerabilityDetail{
						Title: "akonadi - update",
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2023-5981",
						string(vulnerability.Debian),
					},
					Value: types.VulnerabilityDetail{
						Title: "A vulnerability was found that the response times to malformed ciphert ...",
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2021-33560",
					},
					Value: map[string]interface{}{},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2021-29629",
					},
					Value: map[string]interface{}{},
				},
				{
					Key: []string{
						"vulnerability-id",
						"DSA-3714-1",
					},
					Value: map[string]interface{}{},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2023-5981",
					},
					Value: map[string]interface{}{},
				},
			},
			noBuckets: [][]string{
				{
					"advisory-detail",
					"CVE-2021-29629",
					"debian 9",
				}, // not-affected in debian stretch
				{
					"advisory-detail",
					"CVE-2016-4606",
				}, // not-affected in sid
			},
		},
		{
			name:    "sad broken distributions",
			dir:     filepath.Join("testdata", "broken-distributions"),
			wantErr: "failed to decode Debian distribution JSON",
		},
		{
			name:    "sad broken packages",
			dir:     filepath.Join("testdata", "broken-packages"),
			wantErr: "failed to decode testdata/broken-packages/",
		},
		{
			name:    "sad broken CVE",
			dir:     filepath.Join("testdata", "broken-cve"),
			wantErr: "json decode error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := debian.NewVulnSrc()
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
		release string
		pkgName string
	}
	tests := []struct {
		name     string
		fixtures []string
		args     args
		want     []types.Advisory
		wantErr  string
	}{
		{
			name:     "happy path",
			fixtures: []string{"testdata/fixtures/debian.yaml"},
			args: args{
				release: "10",
				pkgName: "alpine",
			},
			want: []types.Advisory{
				{
					VulnerabilityID: "CVE-2008-5514",
					FixedVersion:    "2.02-3.1",
				},
				{
					VulnerabilityID: "CVE-2021-38370",
					Status:          types.StatusAffected,
				},
			},
		},
		{
			name:     "broken bucket",
			fixtures: []string{"testdata/fixtures/broken.yaml"},
			args: args{
				release: "10",
				pkgName: "alpine",
			},
			wantErr: "failed to get Debian advisories",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := debian.NewVulnSrc()
			vulnsrctest.TestGet(t, vs, vulnsrctest.TestGetArgs{
				Fixtures:   tt.fixtures,
				WantValues: tt.want,
				Release:    tt.args.release,
				PkgName:    tt.args.pkgName,
				WantErr:    tt.wantErr,
			})
		})
	}
}
