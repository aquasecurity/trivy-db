package echo

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
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
					Key: []string{"data-source", "echo"},
					Value: types.DataSource{
						ID:   vulnerability.Echo,
						Name: "Echo",
						URL:  "https://advisory.echohq.com/data.json",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2024-11053", "echo", "curl"},
					Value: types.Advisory{
						FixedVersion: "7.88.1-10+deb12u8",
						Severity:     types.SeverityHigh,
					},
				},
			},
		},
		{
			name:    "sad path",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "json decode error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := NewVulnSrc()
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
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			args: args{
				pkgName: "curl",
			},
			want: []types.Advisory{
				{
					VulnerabilityID: "CVE-2008-5514",
					FixedVersion:    "2.02-3.1",
					Severity:        types.SeverityHigh,
				},
				{
					VulnerabilityID: "CVE-2024-11053",
					FixedVersion:    "7.88.1-10+de12u8",
					Status:          types.StatusAffected,
				},
			},
		},
		{
			name:     "broken bucket",
			fixtures: []string{"testdata/fixtures/broken.yaml"},
			args: args{
				pkgName: "curl",
			},
			wantErr: "failed to get advisories",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := NewVulnSrc()
			vulnsrctest.TestGet(t, vs, vulnsrctest.TestGetArgs{
				Fixtures:   tt.fixtures,
				WantValues: tt.want,
				GetParams: db.GetParams{
					PkgName: tt.args.pkgName,
				},
				WantErr: tt.wantErr,
			})
		})
	}
}
