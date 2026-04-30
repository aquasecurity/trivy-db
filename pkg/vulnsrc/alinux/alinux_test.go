package alinux_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/alinux"
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
				// DataSource for alinux 2
				{
					Key: []string{"data-source", "alinux 2"},
					Value: types.DataSource{
						ID:   vulnerability.Alinux,
						Name: "Alibaba Cloud Linux Security Center",
						URL:  "https://alas.aliyuncs.com/",
					},
				},
				// Advisory for postgresql (alinux 2) - from ALINUX2-SA-2025:0006
				{
					Key: []string{"advisory-detail", "CVE-2024-10979", "alinux 2", "postgresql"},
					Value: types.Advisory{
						FixedVersion: "9.2.24-9.1.al7.2",
					},
				},
				// Advisory for postgresql-server (alinux 2) - from ALINUX2-SA-2025:0006
				{
					Key: []string{"advisory-detail", "CVE-2024-10979", "alinux 2", "postgresql-server"},
					Value: types.Advisory{
						FixedVersion: "9.2.24-9.1.al7.2",
					},
				},
				// Vulnerability detail for CVE-2024-10979 (enriched with VEX data from CSAF)
				{
					Key: []string{"vulnerability-detail", "CVE-2024-10979", string(vulnerability.Alinux)},
					Value: types.VulnerabilityDetail{
						Severity:     3, // SeverityHigh from VEX threat "Important"
						Description:  "Incorrect control of environment variables in PostgreSQL PL/Perl allows an unprivileged database user to change sensitive process environment variables (e.g. PATH).  That often suffices to enable arbitrary code execution, even if the attacker lacks a database server operating system user.  Versions before PostgreSQL 17.1, 16.5, 15.9, 14.14, 13.17, and 12.21 are affected.",
						References:   []string{"https://alas.aliyun-inc.com/cves/detail/CVE-2024-10979"},
						CvssVectorV3: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
						CvssScoreV3:  8.8,
					},
				},
				// DataSource for alinux 3
				{
					Key: []string{"data-source", "alinux 3"},
					Value: types.DataSource{
						ID:   vulnerability.Alinux,
						Name: "Alibaba Cloud Linux Security Center",
						URL:  "https://alas.aliyuncs.com/",
					},
				},
				// Advisory for glib2 (alinux 3) - from ALINUX3-SA-2026:0021
				{
					Key: []string{"advisory-detail", "CVE-2025-13601", "alinux 3", "glib2"},
					Value: types.Advisory{
						FixedVersion: "2.68.4-18.0.1.al8.1",
					},
				},
				// Advisory for glib2-devel (alinux 3) - from ALINUX3-SA-2026:0021
				{
					Key: []string{"advisory-detail", "CVE-2025-13601", "alinux 3", "glib2-devel"},
					Value: types.Advisory{
						FixedVersion: "2.68.4-18.0.1.al8.1",
					},
				},
				// Vulnerability detail for CVE-2025-13601 (no VEX enrichment)
				{
					Key: []string{"vulnerability-detail", "CVE-2025-13601", string(vulnerability.Alinux)},
					Value: types.VulnerabilityDetail{
						Severity:     2, // SeverityMedium from advisory "Moderate"
						Description:  "Package updates are available for Alibaba Cloud Linux 3 that fix the following vulnerabilities:\n\nCVE-2025-13601:\nA heap-based buffer overflow problem was found in glib through an incorrect calculation of buffer size in the g_escape_uri_string() function. If the string to escape contains a very large number of unacceptable characters (which would need escaping), the calculation of the length of the escaped string could overflow, leading to a potential write off the end of the newly allocated string.",
						References:   []string{"https://alas.aliyun-inc.com/cves/detail/CVE-2025-13601"},
						CvssVectorV3: "7.7/CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
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
			vs := alinux.NewVulnSrc()
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
			version:  "2",
			pkgName:  "postgresql",
			want:     []types.Advisory{{VulnerabilityID: "CVE-2024-10979", FixedVersion: "9.2.24-9.1.al7.2"}},
		},
		{
			name:     "different version",
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			version:  "3",
			pkgName:  "glib2",
			want:     []types.Advisory{{VulnerabilityID: "CVE-2025-13601", FixedVersion: "2.68.4-18.0.1.al8.1"}},
		},
		{
			name:     "no advisories are returned",
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			version:  "4",
			pkgName:  "postgresql",
		},
		{
			name:     "GetAdvisories returns an error",
			version:  "2",
			pkgName:  "postgresql",
			fixtures: []string{"testdata/fixtures/sad.yaml"},
			wantErr:  "json unmarshal error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := alinux.NewVulnSrc()
			vulnsrctest.TestGet(t, vs, vulnsrctest.TestGetArgs{
				Fixtures:   tt.fixtures,
				WantValues: tt.want,
				GetParams: db.GetParams{
					Release: tt.version,
					PkgName: tt.pkgName,
				},
				WantErr: tt.wantErr,
			})
		})
	}
}
