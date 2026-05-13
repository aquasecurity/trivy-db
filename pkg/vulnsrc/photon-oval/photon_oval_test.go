package photonoval_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	photonoval "github.com/aquasecurity/trivy-db/pkg/vulnsrc/photon-oval"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
)

func TestMain(m *testing.M) {
	utils.Quiet = true
	os.Exit(m.Run())
}

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
				// Photon OS 5.0 data source
				{
					Key: []string{"data-source", "Photon OS OVAL 5.0"},
					Value: types.DataSource{
						ID:   vulnerability.PhotonOVAL,
						Name: "Photon OS OVAL definitions",
						URL:  "https://packages.broadcom.com/photon/photon_oval_definitions/",
					},
				},
				// libcap advisory for CVE-2023-2602
				{
					Key: []string{"advisory-detail", "CVE-2023-2602", "Photon OS OVAL 5.0", "libcap"},
					Value: types.Advisory{
						FixedVersion: "2.66-2.ph5",
						VendorIDs:    []string{"PHSA-2023-5.0-20"},
					},
				},
				// libcap-devel advisory for CVE-2023-2602
				{
					Key: []string{"advisory-detail", "CVE-2023-2602", "Photon OS OVAL 5.0", "libcap-devel"},
					Value: types.Advisory{
						FixedVersion: "2.66-2.ph5",
						VendorIDs:    []string{"PHSA-2023-5.0-20"},
					},
				},
				// libcap advisory for CVE-2023-2603
				{
					Key: []string{"advisory-detail", "CVE-2023-2603", "Photon OS OVAL 5.0", "libcap"},
					Value: types.Advisory{
						FixedVersion: "2.66-2.ph5",
						VendorIDs:    []string{"PHSA-2023-5.0-20"},
					},
				},
				// libcap-devel advisory for CVE-2023-2603
				{
					Key: []string{"advisory-detail", "CVE-2023-2603", "Photon OS OVAL 5.0", "libcap-devel"},
					Value: types.Advisory{
						FixedVersion: "2.66-2.ph5",
						VendorIDs:    []string{"PHSA-2023-5.0-20"},
					},
				},
				// vulnerability details
				{
					Key: []string{"vulnerability-detail", "CVE-2023-2602", "photon-oval"},
					Value: types.VulnerabilityDetail{
						Severity: types.SeverityHigh,
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2023-2603", "photon-oval"},
					Value: types.VulnerabilityDetail{
						Severity: types.SeverityHigh,
					},
				},
				// vulnerability IDs
				{
					Key:   []string{"vulnerability-id", "CVE-2023-2602"},
					Value: map[string]any{},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2023-2603"},
					Value: map[string]any{},
				},
				// Photon OS 4.0 data source
				{
					Key: []string{"data-source", "Photon OS OVAL 4.0"},
					Value: types.DataSource{
						ID:   vulnerability.PhotonOVAL,
						Name: "Photon OS OVAL definitions",
						URL:  "https://packages.broadcom.com/photon/photon_oval_definitions/",
					},
				},
				// curl advisory for CVE-2023-23914 (Moderate -> Medium)
				{
					Key: []string{"advisory-detail", "CVE-2023-23914", "Photon OS OVAL 4.0", "curl"},
					Value: types.Advisory{
						FixedVersion: "7.87.0-3.ph4",
						VendorIDs:    []string{"PHSA-2023-4.0-20"},
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2023-23914", "photon-oval"},
					Value: types.VulnerabilityDetail{
						Severity: types.SeverityMedium,
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2023-23914"},
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
			vs := photonoval.NewVulnSrc()
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
			release:  "5.0",
			pkgName:  "libcap",
			want: []types.Advisory{
				{
					VulnerabilityID: "CVE-2023-2602",
					FixedVersion:    "2.66-2.ph5",
					VendorIDs:       []string{"PHSA-2023-5.0-20"},
				},
			},
		},
		{
			name:     "no advisories are returned",
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			release:  "5.0",
			pkgName:  "no-such-package",
			want:     nil,
		},
		{
			name:     "GetAdvisories returns an error",
			fixtures: []string{"testdata/fixtures/sad.yaml"},
			release:  "5.0",
			pkgName:  "libcap",
			wantErr:  "json unmarshal error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := photonoval.NewVulnSrc()
			vulnsrctest.TestGet(t, vs, vulnsrctest.TestGetArgs{
				Fixtures:   tt.fixtures,
				WantValues: tt.want,
				GetParams: db.GetParams{
					Release: tt.release,
					PkgName: tt.pkgName,
				},
				WantErr: tt.wantErr,
			})
		})
	}
}
