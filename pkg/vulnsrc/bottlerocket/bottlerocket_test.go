package bottlerocket_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bottlerocket"
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
				{
					Key: []string{"data-source", "bottlerocket"},
					Value: types.DataSource{
						ID:   vulnerability.Bottlerocket,
						Name: "Bottlerocket Security Advisories",
						URL:  "https://advisories.bottlerocket.aws/",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2023-5345", "bottlerocket", "kernel-6.1"},
					Value: types.Advisory{
						FixedVersion: "6.1.61-1.1700513487.br1",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2025-22870", "bottlerocket", "amazon-ssm-agent"},
					Value: types.Advisory{
						FixedVersion: "3.3.2746.0-1.1754950980.06e00082.br1",
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2023-5345", string(vulnerability.Bottlerocket)},
					Value: types.VulnerabilityDetail{
						Title:       "kernel CVE-2023-5345",
						Severity:    types.SeverityMedium,
						Description: "A flaw was found in the SMB client component in the Linux kernel.",
						References: []string{
							"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-5345",
							"https://github.com/bottlerocket-os/bottlerocket/security/advisories/GHSA-868r-x68r-5c5p",
						},
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2025-22870", string(vulnerability.Bottlerocket)},
					Value: types.VulnerabilityDetail{
						Title:       "amazon-ssm-agent CVE-2025-22870",
						Severity:    types.SeverityHigh,
						Description: "A flaw was found in amazon-ssm-agent dependency golang.org/x/net.",
						References: []string{
							"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-22870",
							"https://github.com/bottlerocket-os/bottlerocket-core-kit/blob/develop/advisories/10.1.0/BRSA-hc1ikaaaqfgw.toml",
						},
					},
				},
			},
		},
		{
			name:    "sad path",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "json decode error",
		},
		{
			name:    "no such directory",
			dir:     filepath.Join("testdata", "nosuch"),
			wantErr: "no such file or directory",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := bottlerocket.NewVulnSrc()
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
		pkgName  string
		want     []types.Advisory
		wantErr  string
	}{
		{
			name:     "happy path",
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			pkgName:  "kernel-6.1",
			want:     []types.Advisory{{VulnerabilityID: "CVE-2023-5345", FixedVersion: "6.1.61-1.1700513487.br1"}},
		},
		{
			name:     "no advisories are returned",
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			pkgName:  "nonexistent-pkg",
		},
		{
			name:     "GetAdvisories returns an error",
			pkgName:  "kernel-6.1",
			fixtures: []string{"testdata/fixtures/sad.yaml"},
			wantErr:  "json unmarshal error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := bottlerocket.NewVulnSrc()
			vulnsrctest.TestGet(t, vs, vulnsrctest.TestGetArgs{
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
