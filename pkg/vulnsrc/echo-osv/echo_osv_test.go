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
						"echo pip::Echo OSV",
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
						"echo pip::Echo OSV",
						"requests",
					},
					Value: types.Advisory{
						VendorIDs: []string{
							"ECHO-2024-1234",
						},
						PatchedVersions:    []string{"2.14.2+echo.999"},
						VulnerableVersions: []string{">=2.14.2+echo.1, <2.14.2+echo.999"},
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
						Description:  "The requests library before 2.14.2+echo.999 has a vulnerability that allows an attacker to perform SSRF attacks.",
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
				// Maven (Echo:Maven) advisories are stored under the
				// "echo maven::Echo OSV" bucket, keyed by groupId:artifactId.
				{
					Key: []string{
						"data-source",
						"echo maven::Echo OSV",
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
						"CVE-2024-88888",
						"echo maven::Echo OSV",
						"org.apache.commons:commons-lang3",
					},
					Value: types.Advisory{
						VendorIDs: []string{
							"ECHO-2024-4321",
						},
						PatchedVersions:    []string{"3.14.0+echo.999"},
						VulnerableVersions: []string{">=3.14.0+echo.1, <3.14.0+echo.999"},
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2024-88888",
					},
					Value: map[string]any{},
				},
				// npm (Echo:npm) advisories are stored under the
				// "echo npm::Echo OSV" bucket; scoped names keep the
				// "@scope/name" form.
				{
					Key: []string{
						"data-source",
						"echo npm::Echo OSV",
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
						"CVE-2024-66666",
						"echo npm::Echo OSV",
						"@babel/traverse",
					},
					Value: types.Advisory{
						VendorIDs: []string{
							"ECHO-2024-2468",
						},
						PatchedVersions:    []string{"7.23.2+echo.999"},
						VulnerableVersions: []string{">=7.23.2+echo.1, <7.23.2+echo.999"},
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2024-66666",
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
				// Plain "Echo" ecosystem entries are OS packages, owned by
				// the `echo` source. They must not leak into echo-osv buckets.
				{
					"advisory-detail",
					"CVE-2024-77777",
				},
				{
					"vulnerability-detail",
					"CVE-2024-77777",
				},
				{
					"vulnerability-id",
					"CVE-2024-77777",
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
