package wolfi_test

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/wolfi"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
)

var source = types.DataSource{
	ID:   vulnerability.Wolfi,
	Name: "Wolfi Security Data",
	URL:  "https://advisories.cgr.dev/chainguard/v3/osv/all.json",
}

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
					Key:   []string{"data-source", "wolfi"},
					Value: source,
				},
				{
					// Fixed in the same version on both architectures, so the
					// architectures are merged into a single entry.
					Key: []string{"advisory-detail", "CVE-2022-38126", "wolfi", "binutils"},
					Value: types.Advisories{
						FixedVersion: "2.39-r1",
						Entries: []types.Advisory{
							{
								FixedVersion: "2.39-r1",
								Arches: []string{
									"aarch64",
									"x86_64",
								},
								// One advisory per architecture contributed to
								// the outcome.
								VendorIDs: []string{
									"CGA-2222-2222-2222",
									"CGA-3333-3333-3333",
								},
							},
						},
					},
				},
				{
					// Unresolved, so no fixed version is offered and the reason
					// is kept as the status.
					Key: []string{"advisory-detail", "CVE-2022-38533", "wolfi", "binutils"},
					Value: types.Advisories{
						Entries: []types.Advisory{
							{
								Status:    types.StatusFixDeferred,
								Arches:    []string{"x86_64"},
								VendorIDs: []string{"CGA-4444-4444-4444"},
							},
						},
					},
				},
			},
			noBuckets: [][]string{
				// A false positive determination means the package is not
				// affected, so nothing is stored for it.
				{"advisory-detail", "CVE-2022-99999"},
				// Advisories with no CVE ID cannot be reported against a CVE.
				{"advisory-detail", "GHSA-6666-6666-6666"},
				{"advisory-detail", "GO-2026-6666"},
				// A Chainguard package file must not land in the Wolfi bucket.
				{"advisory-detail", "CVE-2022-77777"},
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
			vs := wolfi.NewVulnSrc()
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
		name     string
		fixtures []string
		params   db.GetParams
		want     []types.Advisory
		wantErr  string
	}{
		{
			name:     "advisories are returned for every architecture",
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			params:   db.GetParams{PkgName: "binutils"},
			want: []types.Advisory{
				{
					VulnerabilityID: "CVE-2022-38126",
					FixedVersion:    "2.39-r1",
					Arches: []string{
						"aarch64",
						"x86_64",
					},
					VendorIDs:  []string{"CGA-2222-2222-2222"},
					DataSource: &source,
				},
				{
					VulnerabilityID: "CVE-2022-38533",
					Status:          types.StatusFixDeferred,
					Arches:          []string{"x86_64"},
					VendorIDs:       []string{"CGA-4444-4444-4444"},
					DataSource:      &source,
				},
				{
					VulnerabilityID: "CVE-2022-40000",
					Status:          types.StatusAffected,
					Arches:          []string{"aarch64"},
					VendorIDs:       []string{"CGA-8888-8888-8888"},
					DataSource:      &source,
				},
				{
					VulnerabilityID: "CVE-2022-40000",
					FixedVersion:    "3.0-r0",
					Arches:          []string{"x86_64"},
					VendorIDs:       []string{"CGA-9999-9999-9999"},
					DataSource:      &source,
				},
				{
					VulnerabilityID: "CVE-2022-41000",
					FixedVersion:    "4.0-r0",
					VendorIDs:       []string{"CGA-aaaa-aaaa-aaaa"},
					DataSource:      &source,
				},
			},
		},
		{
			name:     "unknown package",
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			params:   db.GetParams{PkgName: "unknown"},
			want:     nil,
		},
		{
			name:     "broken advisory",
			fixtures: []string{"testdata/fixtures/broken.yaml"},
			params:   db.GetParams{PkgName: "binutils"},
			wantErr:  "json unmarshal error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := wolfi.NewVulnSrc()
			vulnsrctest.TestGet(t, vs, vulnsrctest.TestGetArgs{
				Fixtures:   tt.fixtures,
				WantValues: tt.want,
				GetParams:  tt.params,
				WantErr:    tt.wantErr,
			})
		})
	}
}
