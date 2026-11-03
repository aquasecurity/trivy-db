package cleanstart_test

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/cleanstart"
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
					Key: []string{"data-source", "cleanstart"},
					Value: types.DataSource{
						ID:   vulnerability.CleanStart,
						Name: "CleanStart Security Advisories",
						URL:  "https://github.com/cleanstart-dev/cleanstart-security-advisories",
					},
				},
				// The advisory has no upstream CVE, so the GHSA is used - normalized to
				// the casing the rest of trivy-db keys GHSA advisories with.
				{
					Key: []string{"advisory-detail", "GHSA-hr2v-4r36-88hr", "cleanstart", "cert-manager-cmctl-fips"},
					Value: types.Advisory{
						FixedVersion: "2.4.0-r3",
					},
				},
				// Listed twice, at 0.8.11-r0 and 0.8.10-r1 in that order. The highest wins,
				// so this also proves it is not simply the last entry that is kept.
				{
					Key: []string{"advisory-detail", "GHSA-hr2v-4r36-88hr", "cleanstart", "k8ssandra-client-fips"},
					Value: types.Advisory{
						FixedVersion: "0.8.11-r0",
					},
				},
				// Listed twice, at 26.4.2 and 26.1.4-r0.
				{
					Key: []string{"advisory-detail", "GHSA-hr2v-4r36-88hr", "cleanstart", "linkerd2"},
					Value: types.Advisory{
						FixedVersion: "26.4.2",
					},
				},
				{
					Key: []string{"vulnerability-detail", "GHSA-hr2v-4r36-88hr", string(vulnerability.CleanStart)},
					Value: types.VulnerabilityDetail{
						Title:       "Security fix for ghsa-hr2v-4r36-88hr applied in: cert-manager-cmctl-fips 2.4.0-r3, k8ssandra-client-fips 0.8.10-r1, k8ssandra-client-fips 0.8.11-r0, linkerd2 26.1.4-r0, linkerd2 26.4.2",
						Description: "ghsa-hr2v-4r36-88hr affects multiple packages. This issue is resolved in later releases. See references for individual vulnerability details.",
						References: []string{
							"https://github.com/cleanstart-dev/cleanstart-security-advisories/tree/main/advisories/2026/CLEANSTART-2026-AA09584.json",
							"https://osv.dev/vulnerability/ghsa-hr2v-4r36-88hr",
						},
						// The feed writes CVSSv2 vectors bare, with no "CVSS:2.0/" prefix.
						CvssScore:  7.5,
						CvssVector: "AV:N/AC:L/Au:N/C:P/I:P/A:P",
					},
				},
				{
					Key:   []string{"vulnerability-id", "GHSA-hr2v-4r36-88hr"},
					Value: map[string]any{},
				},

				// The advisory lists both a GHSA and a CVE upstream. The CVE wins, because
				// NVD supplies severity and description for it, and the GHSA is an alias.
				{
					Key: []string{"advisory-detail", "CVE-2026-1111", "cleanstart", "redis"},
					Value: types.Advisory{
						FixedVersion: "7.4.6-r0",
					},
				},
				// CleanStart's own CVSS is stored, so trivy can report a severity for a CVE
				// that NVD has not scored yet.
				{
					Key: []string{"vulnerability-detail", "CVE-2026-1111", string(vulnerability.CleanStart)},
					Value: types.VulnerabilityDetail{
						Title:         "Security fix for cve-2026-1111 applied in: redis 7.4.6-r0",
						Description:   "cve-2026-1111 affects redis. This issue is resolved in later releases.",
						References:    []string{"https://github.com/cleanstart-dev/cleanstart-security-advisories/tree/main/advisories/2026/CLEANSTART-2026-BB00001.json"},
						CvssScoreV3:   9.8,
						CvssVectorV3:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
						CvssScoreV40:  9.3,
						CvssVectorV40: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2026-1111"},
					Value: map[string]any{},
				},

				// One CVE fixed on four maintained branches. Keeping a lower branch's fix
				// would report an unpatched build on a newer branch (e.g. 2.14.1) as fixed.
				{
					Key: []string{"advisory-detail", "CVE-2021-3538", "cleanstart", "harbor"},
					Value: types.Advisory{
						FixedVersion: "2.15.0-r0",
					},
				},
				// The CVSS vector is malformed, so it is dropped and the advisory is still stored.
				{
					Key: []string{"vulnerability-detail", "CVE-2021-3538", string(vulnerability.CleanStart)},
					Value: types.VulnerabilityDetail{
						Title:       "Security fix for CVE-2021-3538 applied in: harbor 2.12.4-r0, harbor 2.13.5-r0, harbor 2.14.3-r0, harbor 2.15.0-r0",
						Description: "CVE-2021-3538 affects multiple packages. This issue is resolved in later releases. See references for individual vulnerability details.",
					},
				},

				// No upstream at all, so the CleanStart ID is used. The Go package in the
				// same advisory is not a CleanStart package and must not be stored.
				{
					Key: []string{"advisory-detail", "CLEANSTART-2026-CC00002", "cleanstart", "nginx"},
					Value: types.Advisory{
						FixedVersion: "1.29.3-r0",
					},
				},
				{
					Key:   []string{"vulnerability-id", "CLEANSTART-2026-CC00002"},
					Value: map[string]any{},
				},
			},
			noBuckets: [][]string{
				// The advisory was stored under its upstream GHSA, so storing it under
				// the CleanStart ID too would report the same fix twice.
				{"advisory-detail", "CLEANSTART-2026-AA09584"},
				// The GHSA is an alias of CVE-2026-1111 and must not be stored alongside it.
				{"advisory-detail", "GHSA-aaaa-bbbb-cccc"},
				// Every affected package belongs to another ecosystem, so nothing is stored.
				{"advisory-detail", "CVE-2026-2222"},
			},
		},
		{
			name:    "sad path",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "json decode error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := cleanstart.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				NoBuckets:  tt.noBuckets,
				WantErr:    tt.wantErr,
			})
		})
	}
}

func TestVulnSrc_Get(t *testing.T) {
	tests := []struct {
		name       string
		fixtures   []string
		params     db.GetParams
		wantValues []types.Advisory
		wantErr    string
	}{
		{
			name:     "happy path",
			fixtures: []string{"testdata/fixtures/cleanstart.yaml"},
			params: db.GetParams{
				PkgName: "linkerd2",
			},
			wantValues: []types.Advisory{
				{
					VulnerabilityID: "GHSA-hr2v-4r36-88hr",
					FixedVersion:    "26.1.4-r0",
				},
			},
		},
		{
			name:     "no advisories",
			fixtures: []string{"testdata/fixtures/cleanstart.yaml"},
			params: db.GetParams{
				PkgName: "not-affected",
			},
			wantValues: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := cleanstart.NewVulnSrc()
			vulnsrctest.TestGet(t, vs, vulnsrctest.TestGetArgs{
				Fixtures:   tt.fixtures,
				GetParams:  tt.params,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
			})
		})
	}
}
