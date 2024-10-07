package photon

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
					Key: []string{"data-source", "Photon OS 3.0"},
					Value: types.DataSource{
						ID:   vulnerability.Photon,
						Name: "Photon OS CVE metadata",
						URL:  "https://packages.vmware.com/photon/photon_cve_metadata/",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2019-0199", "Photon OS 3.0", "apache-tomcat"},
					Value: types.Advisory{
						FixedVersion: "8.5.40-1.ph3",
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2019-0199", "photon"},
					Value: types.VulnerabilityDetail{
						CvssScoreV3: 7.5,
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2019-0199"},
					Value: map[string]interface{}{},
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
			wantErr: "failed to decode Photon JSON",
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
	tests := []struct {
		name     string
		fixtures []string
		release  string
		pkgName  string
		want     []types.Advisory
		wantErr  string
	}{
		{
			name:     "happy path",
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			release:  "1.0",
			pkgName:  "ansible",
			want: []types.Advisory{
				{
					VulnerabilityID: "CVE-2019-3828",
					FixedVersion:    "2.7.6-2.ph3",
				},
			},
		},
		{
			name:     "no advisories are returned",
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			release:  "2.0",
			pkgName:  "ansible",
			want:     nil,
		},
		{
			name:     "GetAdvisories returns an error",
			fixtures: []string{"testdata/fixtures/sad.yaml"},
			release:  "1.0",
			pkgName:  "ansible",
			wantErr:  "failed to unmarshal advisory JSON",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := NewVulnSrc()
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
