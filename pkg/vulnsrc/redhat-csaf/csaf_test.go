package redhatcsaf_test

import (
	"os"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	redhatcsaf "github.com/aquasecurity/trivy-db/pkg/vulnsrc/redhat-csaf"
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
			dir:  "testdata",
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{
						"data-source",
						"Red Hat",
					},
					Value: types.DataSource{
						ID:   vulnerability.RedHatCSAFVEX,
						Name: "Red Hat CSAF VEX",
						URL:  "https://access.redhat.com/security/data/csaf/v2/vex/",
					},
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"0",
					},
					Value: "cpe:/o:redhat:enterprise_linux:8::baseos",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"1",
					},
					Value: "cpe:/o:redhat:enterprise_linux:9::baseos",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"repository",
						"rhel-8-for-x86_64-baseos-rpms",
					},
					Value: []int{0},
				},
				{
					Key: []string{
						"Red Hat CPE",
						"nvr",
						"pam-1.5.1-21.el9_5.x86_64",
					},
					Value: []int{1},
				},
				{
					Key: []string{
						"advisory-detail",
						"RHSA-2024:9941",
						"Red Hat",
						"pam",
					},
					Value: redhatcsaf.Advisory{
						Entries: []redhatcsaf.Entry{
							{
								FixedVersion: "1.5.1-21.el9_5",
								CVEs: []redhatcsaf.CVEEntry{
									{
										ID:       "CVE-2024-10041",
										Severity: types.SeverityMedium,
									},
								},
								Arches:             []string{"aarch64", "x86_64"},
								AffectedCPEIndices: []int{1},
							},
						},
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"RHSA-2024:9999",
						"Red Hat",
						"test-namespace/test-package",
					},
					Value: redhatcsaf.Advisory{
						Entries: []redhatcsaf.Entry{
							{
								FixedVersion: "1:1.0.0-1.el9",
								CVEs: []redhatcsaf.CVEEntry{
									{
										ID:       "CVE-2024-9999",
										Severity: types.SeverityHigh,
									},
								},
								Arches:             []string{"x86_64"},
								AffectedCPEIndices: []int{1},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := redhatcsaf.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
			})
		})
	}
}
