package azure_test

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/azure"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
)

func TestVulnSrc_Update(t *testing.T) {
	tests := []struct {
		name       string
		dir        string
		wantValues []vulnsrctest.WantValues
		wantErr    string
		noBuckets  [][]string
	}{
		{
			name: "happy path",
			dir:  filepath.Join("testdata", "happy"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"data-source", "Azure Linux 3.0"},
					Value: types.DataSource{
						ID:   vulnerability.AzureLinux,
						Name: "Azure Linux Vulnerability Data",
						URL:  "https://github.com/microsoft/AzureLinuxVulnerabilityData",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2018-1999023", "Azure Linux 3.0", "ceph"},
					Value: types.Advisory{
						FixedVersion: "0:18.2.1-1.azl3",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2023-27534", "Azure Linux 3.0", "tensorflow"},
					Value: types.Advisory{
						FixedVersion: "0:2.16.1-1.azl3",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := azure.NewVulnSrc()
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
	tests := []struct {
		name     string
		release  string
		pkgName  string
		fixtures []string
		want     []types.Advisory
		wantErr  string
	}{
		{
			name:     "happy path",
			release:  "3.0",
			pkgName:  "ceph",
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			want: []types.Advisory{
				{
					VulnerabilityID: "CVE-2018-1999023",
					FixedVersion:    "0:18.2.1-1.azl3",
				},
			},
		},
		{
			name:     "unknown package",
			release:  "3.0",
			pkgName:  "unknown-package",
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			want:     []types.Advisory(nil),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := azure.NewVulnSrc()
			vulnsrctest.TestGet(t, vs, vulnsrctest.TestGetArgs{
				Fixtures:   tt.fixtures,
				WantValues: tt.want,
				Release:    tt.release,
				PkgName:    tt.pkgName,
				WantErr:    tt.wantErr,
			})
		})
	}
}
