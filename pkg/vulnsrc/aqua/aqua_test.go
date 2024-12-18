package aqua_test

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/aqua"
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
						"pip::The Aqua Security Vulnerability Database",
					},
					Value: types.DataSource{
						ID:   vulnerability.Aqua,
						Name: "The Aqua Security Vulnerability Database",
						URL:  "https://github.com/aquasecurity/vuln-list-aqua",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"AQUA-2024-0001",
						"pip::The Aqua Security Vulnerability Database",
						"ultralytics",
					},
					Value: types.Advisory{
						PatchedVersions: []string{
							"8.3.43",
							"8.3.47",
						},
						VulnerableVersions: []string{
							">=8.3.41, <8.3.43",
							">=8.3.45, <8.3.47",
						},
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"AQUA-2024-0001",
						"aqua",
					},
					Value: types.VulnerabilityDetail{
						Title:       "Vulnerable app versions contains xmrig cryptominer",
						Description: "Affected versions of this package are vulnerable to Malicious Embedded Code. These versions have been compromised to install an xmrig cryptominer when installed from PyPI (e.g. via default pip options, without specifying a git URL).",
						References: []string{
							"https://github.com/ultralytics/ultralytics/issues/18027",
							"https://github.com/ultralytics/ultralytics/issues/18030",
						},
						CvssScoreV3:  9.8,
						CvssVectorV3: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"AQUA-2024-0001",
					},
					Value: map[string]interface{}{},
				},
			},
			noBuckets: [][]string{
				// We should save only stdlib packages
				{
					"advisory-detail",
					"CVE-2021-41803",
				},
				{
					"vulnerability-detail",
					"CVE-2021-41803",
				},
				{
					"vulnerability-id",
					"CVE-2021-41803",
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
			wantErr: "JSON decode error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := aqua.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
				NoBuckets:  tt.noBuckets,
			})
		})
	}
}
