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
						URL:  "https://advisories.bottlerocket.aws/updateinfo.xml.gz",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2024-43840", "bottlerocket", "kernel-6.1"},
					Value: types.Advisory{
						FixedVersion: "6.1.140-1.1749663821.e27d1b03.br1",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2025-15281", "bottlerocket", "glibc"},
					Value: types.Advisory{
						FixedVersion: "1:2.43-1.1773716061.e2e9d7a9.br1",
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2024-43840", string(vulnerability.Bottlerocket)},
					Value: types.VulnerabilityDetail{
						Title:       "kernel CVE-2024-43840",
						Severity:    types.SeverityMedium,
						Description: "In the Linux kernel, the following vulnerability has been resolved: bpf, arm64: Fix trampoline for BPF_TRAMP_F_CALL_ORIG",
						References: []string{
							"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-43840",
							"https://github.com/bottlerocket-os/bottlerocket-kernel-kit/blob/develop/advisories/3.1.0/BRSA-1bwujdrkn6nc.toml",
						},
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2025-15281", string(vulnerability.Bottlerocket)},
					Value: types.VulnerabilityDetail{
						Title:       "glibc CVE-2025-15281",
						Severity:    types.SeverityMedium,
						Description: "In the GNU C Library, calling wordexp with WRDE_REUSE and WRDE_APPEND may cause uninitialized memory to be returned in the we_wordv member, which on subsequent calls to wordfree could result in a process abort.",
						References: []string{
							"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-15281",
							"https://github.com/bottlerocket-os/bottlerocket-core-kit/blob/develop/advisories/13.2.0/BRSA-kdg8bd1th2gb.toml",
						},
					},
				},
				{
					// Advisory without a CVE reference: recorded under its BRSA ID.
					Key: []string{"advisory-detail", "BRSA-bbybjyf8opyg", "bottlerocket", "kernel-6.1"},
					Value: types.Advisory{
						FixedVersion: "6.1.161-1.1770431693.0286af16.br1",
					},
				},
				{
					Key: []string{"vulnerability-detail", "BRSA-bbybjyf8opyg", string(vulnerability.Bottlerocket)},
					Value: types.VulnerabilityDetail{
						Title:       "Bottlerocket Kernel 6.1 Updates",
						Severity:    types.SeverityHigh,
						Description: "Kernel version 6.1.161 is now available with important fixes. All users must upgrade. Advisory information for kernel is often published after new kernels become available. Bottlerocket recommends that you consume the latest kernel release for your LTS version.",
						References: []string{
							"https://github.com/bottlerocket-os/bottlerocket-kernel-kit/blob/develop/advisories/4.8.2/BRSA-bbybjyf8opyg.toml",
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
			want:     []types.Advisory{{VulnerabilityID: "CVE-2024-43840", FixedVersion: "6.1.140-1.1749663821.e27d1b03.br1"}},
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
