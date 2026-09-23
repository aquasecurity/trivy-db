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
						URL:  "https://advisory.echohq.com/osv/all.zip",
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
							"GHSA-9999-9999-9999",
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
						References: []string{
							"https://nvd.nist.gov/vuln/detail/CVE-2024-99999",
							"https://github.com/psf/requests",
						},
						LastModifiedDate: utils.MustTimeParse("2024-10-15T12:00:00Z"),
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2024-99999",
					},
					Value: map[string]any{},
				},
				// An entry without a CVE is keyed by its upstream GHSA
				// instead of being dropped.
				{
					Key: []string{
						"advisory-detail",
						"GHSA-1234-5678-9abc",
						"echo pip::Echo OSV",
						"gitpython",
					},
					Value: types.Advisory{
						VendorIDs: []string{
							"ECHO-2024-4321",
						},
						PatchedVersions:    []string{"3.1.57"},
						VulnerableVersions: []string{">=3.1.0, <3.1.57"},
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"GHSA-1234-5678-9abc",
						string(vulnerability.EchoOSV),
					},
					Value: types.VulnerabilityDetail{
						References: []string{
							"https://github.com/advisories/GHSA-1234-5678-9abc",
						},
						LastModifiedDate: utils.MustTimeParse("2024-12-10T09:00:00Z"),
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"GHSA-1234-5678-9abc",
					},
					Value: map[string]any{},
				},
			},
			noBuckets: [][]string{
				{
					"advisory-detail",
					"GHSA-9999-9999-9999",
				},
				{
					"vulnerability-detail",
					"GHSA-9999-9999-9999",
				},
				{
					"vulnerability-id",
					"GHSA-9999-9999-9999",
				},
				{
					"advisory-detail",
					"ECHO-2024-5678",
				},
				// The GHSA-keyed entry must not also be stored under its
				// opaque ECHO ID.
				{
					"advisory-detail",
					"ECHO-2024-4321",
				},
				{
					"vulnerability-detail",
					"ECHO-2024-4321",
				},
				{
					"vulnerability-id",
					"ECHO-2024-4321",
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
