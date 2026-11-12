package dhi_test

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/dhi"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
)

const vulnID = "DHI-CVE-2016-2781-coreutils"

var dataSource = types.DataSource{
	ID:   vulnerability.DHI,
	Name: "Docker Hardened Images Advisories",
	URL:  "https://github.com/docker-hardened-images/advisories",
}

func advisory(bucket string, adv types.Advisory) vulnsrctest.WantValues {
	adv.VendorIDs = []string{"CVE-2016-2781"}
	return vulnsrctest.WantValues{Key: []string{"advisory-detail", vulnID, bucket, "coreutils"}, Value: adv}
}

func TestVulnSrc_Update(t *testing.T) {
	// One advisory covering the same package in two Alpine releases and in Debian. Each
	// release must keep only its own constraints, whatever the order of the affected entries.
	multiRelease := []vulnsrctest.WantValues{
		{Key: []string{"data-source", "dhi alpine 3.23"}, Value: dataSource},
		{Key: []string{"data-source", "dhi alpine 3.24"}, Value: dataSource},
		{Key: []string{"data-source", "dhi debian 13"}, Value: dataSource},
		advisory("dhi alpine 3.23", types.Advisory{VulnerableVersions: []string{"<9.5-r2"}, PatchedVersions: []string{"9.5-r2"}}),
		advisory("dhi alpine 3.24", types.Advisory{VulnerableVersions: []string{"<9.11-r1"}, PatchedVersions: []string{"9.11-r1"}}),
		advisory("dhi debian 13", types.Advisory{VulnerableVersions: []string{"<9.7-3+dhi4"}, PatchedVersions: []string{"9.7-3+dhi4"}}),
	}

	// Fixtures with a malformed or conflicting Alpine 3.24 entry also hold a valid Debian 13
	// entry. Only the bad package is dropped, without failing the build.
	debianOnly := []vulnsrctest.WantValues{
		{Key: []string{"data-source", "dhi debian 13"}, Value: dataSource},
		advisory("dhi debian 13", types.Advisory{VulnerableVersions: []string{"<9.7-3+dhi4"}, PatchedVersions: []string{"9.7-3+dhi4"}}),
	}
	dropped := [][]string{{"advisory-detail", vulnID, "dhi alpine 3.24"}}

	tests := []struct {
		name       string
		dir        string
		wantValues []vulnsrctest.WantValues
		noBuckets  [][]string
	}{
		{
			name: "happy path",
			dir:  "happy",
			wantValues: []vulnsrctest.WantValues{
				{Key: []string{"data-source", "dhi alpine 3.24"}, Value: dataSource},
				advisory("dhi alpine 3.24", types.Advisory{
					VulnerableVersions: []string{"<9.11-r1"}, PatchedVersions: []string{"9.11-r1"}, Arches: []string{"aarch64"},
				}),
			},
		},
		{
			name:       "same package in several releases",
			dir:        "multi-release",
			wantValues: multiRelease,
		},
		{
			name:       "same package in several releases, reversed order",
			dir:        "multi-release-reversed",
			wantValues: multiRelease,
		},
		{
			name: "PURLs without os qualifiers",
			dir:  "qualifier-free",
			wantValues: []vulnsrctest.WantValues{
				advisory("dhi alpine 3.24", types.Advisory{
					VulnerableVersions: []string{"<9.11-r1"}, PatchedVersions: []string{"9.11-r1"}, Arches: []string{"aarch64"},
				}),
				advisory("dhi debian 13", types.Advisory{VulnerableVersions: []string{"<9.7-3+dhi4"}, PatchedVersions: []string{"9.7-3+dhi4"}}),
			},
		},
		{
			name: "ecosystem and qualifiers in another case",
			dir:  "mixed-case",
			wantValues: []vulnsrctest.WantValues{
				{Key: []string{"data-source", "dhi alpine 3.24"}, Value: dataSource},
				advisory("dhi alpine 3.24", types.Advisory{
					VulnerableVersions: []string{"<9.11-r1"}, PatchedVersions: []string{"9.11-r1"}, Arches: []string{"aarch64"},
				}),
			},
		},
		{
			name: "entries with the same architecture are aggregated",
			dir:  "same-arch",
			wantValues: []vulnsrctest.WantValues{
				advisory("dhi alpine 3.24", types.Advisory{
					VulnerableVersions: []string{"<9.11-r1", ">=9.12-r0, <9.12-r3"},
					PatchedVersions:    []string{"9.11-r1", "9.12-r3"},
					Arches:             []string{"aarch64"},
				}),
			},
		},
		{
			name:       "entries with different architectures are dropped",
			dir:        "different-arches",
			wantValues: debianOnly,
			noBuckets:  dropped,
		},
		{
			name:       "architecture-scoped entry followed by an unscoped entry is dropped",
			dir:        "arch-then-no-arch",
			wantValues: debianOnly,
			noBuckets:  dropped,
		},
		{
			name:       "os qualifier disagreeing with the ecosystem is dropped",
			dir:        "qualifier-mismatch",
			wantValues: debianOnly,
			noBuckets:  dropped,
		},
		{
			name:       "PURL type disagreeing with the ecosystem lineage is dropped",
			dir:        "lineage-mismatch",
			wantValues: debianOnly,
			noBuckets:  dropped,
		},
		{
			name:       "PURL namespace other than dhi is dropped",
			dir:        "namespace-mismatch",
			wantValues: debianOnly,
			noBuckets:  dropped,
		},
		{
			name:       "ecosystem without lineage and release is dropped",
			dir:        "missing-release",
			wantValues: debianOnly,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vulnsrctest.TestUpdate(t, dhi.NewVulnSrc(), vulnsrctest.TestUpdateArgs{
				Dir:        filepath.Join("testdata", tt.dir),
				WantValues: tt.wantValues,
				NoBuckets:  tt.noBuckets,
			})
		})
	}
}
