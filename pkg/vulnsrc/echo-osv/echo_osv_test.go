package echoosv_test

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	echoosv "github.com/aquasecurity/trivy-db/pkg/vulnsrc/echo-osv"
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
						"pip::Echo OSV",
					},
					Value: types.DataSource{
						ID:   vulnerability.EchoOSV,
						Name: "Echo OSV",
						URL:  "https://advisory.echohq.com/osv",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2024-99999",
						"pip::Echo OSV",
						"requests",
					},
					Value: types.Advisory{
						VendorIDs: []string{
							"ECHO-2024-1234",
						},
						PatchedVersions:    []string{"2.32.0"},
						VulnerableVersions: []string{">=2.0.0, <2.32.0"},
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2024-99999",
						string(vulnerability.EchoOSV),
					},
					Value: types.VulnerabilityDetail{
						Title:        "Example vulnerability in requests library",
						Description:  "The requests library before 2.32.0 has a vulnerability that allows an attacker to perform SSRF attacks.",
						CvssVectorV3: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
						CvssScoreV3:  7.5,
						References: []string{
							"https://nvd.nist.gov/vuln/detail/CVE-2024-99999",
							"https://github.com/psf/requests",
						},
						LastModifiedDate: utils.MustTimeParse("2024-10-15T12:00:00Z"),
						PublishedDate:    utils.MustTimeParse("2024-09-01T08:00:00Z"),
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2024-99999",
					},
					Value: map[string]any{},
				},
			},
			noBuckets: [][]string{
				{
					"advisory-detail",
					"ECHO-2024-5678",
				},
				{
					"vulnerability-detail",
					"ECHO-2024-5678",
				},
				{
					"vulnerability-id",
					"ECHO-2024-5678",
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
			vs := echoosv.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				NoBuckets:  tt.noBuckets,
				WantErr:    tt.wantErr,
			})
		})
	}
}
