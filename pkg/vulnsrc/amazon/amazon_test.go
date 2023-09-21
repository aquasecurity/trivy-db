package amazon_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/amazon"
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
					Key: []string{"data-source", "amazon linux 1"},
					Value: types.DataSource{
						ID:   vulnerability.Amazon,
						Name: "Amazon Linux Security Center",
						URL:  "https://alas.aws.amazon.com/",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2018-17456", "amazon linux 1", "git"},
					Value: types.Advisory{
						FixedVersion: "2.14.5-1.59.amzn1",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2018-17456", "amazon linux 1", "git-debuginfo"},
					Value: types.Advisory{
						FixedVersion: "1:2.14.5-1.59.amzn1",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-22543", "amazon linux 2", "kernel"},
					Value: types.Advisory{
						FixedVersion: "4.14.243-185.433.amzn2",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-22543", "amazon linux 2", "kernel-headers"},
					Value: types.Advisory{
						FixedVersion: "4.14.243-185.433.amzn2",
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2018-17456", "amazon"},
					Value: types.VulnerabilityDetail{
						Severity:    3,
						Description: "Package updates are available for Amazon Linux AMI that fix the following vulnerabilities:\nCVE-2018-17456:\n\tGit before 2.14.5, 2.15.x before 2.15.3, 2.16.x before 2.16.5, 2.17.x before 2.17.2, 2.18.x before 2.18.1, and 2.19.x before 2.19.1 allows remote code execution during processing of a recursive &quot;git clone&quot; of a superproject if a .gitmodules file has a URL field beginning with a &#039;-&#039; character.\n1636619: \nCVE-2018-17456 git: arbitrary code execution via .gitmodules\n",
						References:  []string{"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-17456"},
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2021-22543", "amazon"},
					Value: types.VulnerabilityDetail{
						Severity:    1,
						Description: "Package updates are available for Amazon Linux 2 that fix the following vulnerabilities:\nCVE-2021-22543:\n\tA flaw was found in the Linux kernel's KVM implementation, where improper handing of the VM_IO|VM_PFNMAP VMAs in KVM bypasses RO checks and leads to pages being freed while still accessible by the VMM and guest. This flaw allows users who can start and control a VM to read/write random pages of memory, resulting in local privilege escalation. The highest threat from this vulnerability is to confidentiality, integrity, and system availability.\n1965461: CVE-2021-22543 kernel: Improper handling of VM_IO|VM_PFNMAP vmas in KVM can bypass RO checks\n",
						References:  []string{"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22543"},
					},
				},
				{
					Key: []string{"data-source", "amazon linux 2022"},
					Value: types.DataSource{
						ID:   vulnerability.Amazon,
						Name: "Amazon Linux Security Center",
						URL:  "https://alas.aws.amazon.com/",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-44228", "amazon linux 2022", "log4j"},
					Value: types.Advisory{
						FixedVersion: "2.15.0-1.amzn2022.0.1",
					},
				},
			},
		},
		{
			name:    "sad path",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "failed to decode Amazon JSON",
		},
		{
			name:    "no such directory",
			dir:     filepath.Join("testdata", "nosuch"),
			wantErr: "no such file or directory",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := amazon.NewVulnSrc()
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
		version  string
		pkgName  string
		want     []types.Advisory
		wantErr  string
	}{
		{
			name:     "happy path",
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			version:  "1",
			pkgName:  "curl",
			want:     []types.Advisory{{VulnerabilityID: "CVE-2019-0001", FixedVersion: "0.1.2"}},
		},
		{
			name:     "no advisories are returned",
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			version:  "2",
			pkgName:  "curl",
		},
		{
			name:     "GetAdvisories returns an error",
			version:  "1",
			pkgName:  "curl",
			fixtures: []string{"testdata/fixtures/sad.yaml"},
			wantErr:  "failed to unmarshal advisory JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := amazon.NewVulnSrc()
			vulnsrctest.TestGet(t, vs, vulnsrctest.TestGetArgs{
				Fixtures:   tt.fixtures,
				WantValues: tt.want,
				Release:    tt.version,
				PkgName:    tt.pkgName,
				WantErr:    tt.wantErr,
			})
		})
	}
}
