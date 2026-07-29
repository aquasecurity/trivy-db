package chainguardosv_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/chainguardosv"
)

func fixed(version string) []chainguardosv.Event {
	return []chainguardosv.Event{
		{Introduced: "0"},
		{Fixed: version},
	}
}

func unfixed() []chainguardosv.Event {
	return []chainguardosv.Event{{Introduced: "0"}}
}

func TestAggregate(t *testing.T) {
	tests := []struct {
		name string
		pkg  chainguardosv.Package
		want map[string]types.Advisories
	}{
		{
			name: "no advisories",
			pkg: chainguardosv.Package{
				Ecosystem: "Chainguard",
				Name:      "curl",
			},
			want: map[string]types.Advisories{},
		},
		{
			name: "fixed vulnerability",
			pkg: chainguardosv.Package{
				Ecosystem: "Chainguard",
				Name:      "haproxy-2.2",
				Advisories: []chainguardosv.Advisory{
					{
						ID:       "CGA-hxhw-2p27-xpg6",
						Upstream: []string{"CVE-2025-32464", "GHSA-frg5-h47x-75j9"},
						Arch:     "x86_64",
						Events:   fixed("2.2.34-r0"),
						Status:   "fixed",
					},
				},
			},
			want: map[string]types.Advisories{
				"CVE-2025-32464": {
					FixedVersion: "2.2.34-r0",
					Entries: []types.Advisory{
						{
							FixedVersion: "2.2.34-r0",
							Arches:       []string{"x86_64"},
							VendorIDs:    []string{"CGA-hxhw-2p27-xpg6"},
						},
					},
				},
			},
		},
		{
			name: "several components fixed in different versions, highest wins",
			pkg: chainguardosv.Package{
				Ecosystem: "Chainguard",
				Name:      "busybox",
				Advisories: []chainguardosv.Advisory{
					{
						ID:       "CGA-1111-1111-1111",
						Upstream: []string{"CVE-2024-58251"},
						Arch:     "x86_64",
						Events:   fixed("1.37.0-r9"),
						Status:   "fixed",
					},
					{
						ID:       "CGA-2222-2222-2222",
						Upstream: []string{"CVE-2024-58251"},
						Arch:     "x86_64",
						// APK ordering, not string ordering: r49 is later than r9.
						Events: fixed("1.37.0-r49"),
						Status: "fixed",
					},
					{
						ID:       "CGA-3333-3333-3333",
						Upstream: []string{"CVE-2024-58251"},
						Arch:     "x86_64",
						Events:   fixed("1.37.0-r12"),
						Status:   "fixed",
					},
				},
			},
			want: map[string]types.Advisories{
				"CVE-2024-58251": {
					FixedVersion: "1.37.0-r49",
					Entries: []types.Advisory{
						{
							FixedVersion: "1.37.0-r49",
							Arches:       []string{"x86_64"},
							VendorIDs:    []string{"CGA-2222-2222-2222"},
						},
					},
				},
			},
		},
		{
			name: "an unresolved component keeps the package affected",
			pkg: chainguardosv.Package{
				Ecosystem: "Chainguard",
				Name:      "nginx",
				Advisories: []chainguardosv.Advisory{
					{
						ID:       "CGA-comp-fixed-0000",
						Upstream: []string{"CVE-2026-1000"},
						Arch:     "x86_64",
						Events:   fixed("1.29.0-r0"),
						Status:   "fixed",
					},
					{
						ID:       "CGA-comp-detected-00",
						Upstream: []string{"CVE-2026-1000"},
						Arch:     "x86_64",
						Events:   unfixed(),
						Status:   "detection",
					},
				},
			},
			want: map[string]types.Advisories{
				"CVE-2026-1000": {
					Entries: []types.Advisory{
						{
							Status:    types.StatusUnderInvestigation,
							Arches:    []string{"x86_64"},
							VendorIDs: []string{"CGA-comp-detected-00"},
						},
					},
				},
			},
		},
		{
			name: "all false positives, nothing is affected",
			pkg: chainguardosv.Package{
				Ecosystem: "Chainguard",
				Name:      "actions-runner-controller",
				Advisories: []chainguardosv.Advisory{
					{
						ID:       "CGA-4v68-6h73-hv9c",
						Upstream: []string{"CVE-2026-32288"},
						Arch:     "aarch64",
						Events:   fixed("0"),
						Status:   "false_positive_determination",
					},
					{
						ID:       "CGA-4v68-6h73-hv9d",
						Upstream: []string{"CVE-2026-32288"},
						Arch:     "aarch64",
						Events:   fixed("0"),
						Status:   "false_positive_determination",
					},
				},
			},
			want: map[string]types.Advisories{},
		},
		{
			name: "a false positive does not hide a fix for another component",
			pkg: chainguardosv.Package{
				Ecosystem: "Chainguard",
				Name:      "curl",
				Advisories: []chainguardosv.Advisory{
					{
						ID:       "CGA-fp00-0000-0000",
						Upstream: []string{"CVE-2026-2000"},
						Arch:     "x86_64",
						Events:   fixed("0"),
						Status:   "false_positive_determination",
					},
					{
						ID:       "CGA-fix0-0000-0000",
						Upstream: []string{"CVE-2026-2000"},
						Arch:     "x86_64",
						Events:   fixed("8.4.0-r0"),
						Status:   "fixed",
					},
				},
			},
			want: map[string]types.Advisories{
				"CVE-2026-2000": {
					FixedVersion: "8.4.0-r0",
					Entries: []types.Advisory{
						{
							FixedVersion: "8.4.0-r0",
							Arches:       []string{"x86_64"},
							VendorIDs:    []string{"CGA-fix0-0000-0000"},
						},
					},
				},
			},
		},
		{
			name: "the most pressing unresolved status is reported",
			pkg: chainguardosv.Package{
				Ecosystem: "Chainguard",
				Name:      "ko",
				Advisories: []chainguardosv.Advisory{
					{
						ID:       "CGA-detect-0000-00",
						Upstream: []string{"CVE-2026-3000"},
						Arch:     "x86_64",
						Events:   unfixed(),
						Status:   "detection",
					},
					{
						ID:       "CGA-truepos-000-00",
						Upstream: []string{"CVE-2026-3000"},
						Arch:     "x86_64",
						Events:   unfixed(),
						Status:   "true_positive_determination",
					},
					{
						ID:       "CGA-pending-000-00",
						Upstream: []string{"CVE-2026-3000"},
						Arch:     "x86_64",
						Events:   unfixed(),
						Status:   "pending_upstream_fix",
					},
				},
			},
			want: map[string]types.Advisories{
				"CVE-2026-3000": {
					Entries: []types.Advisory{
						{
							Status:    types.StatusAffected,
							Arches:    []string{"x86_64"},
							VendorIDs: []string{"CGA-truepos-000-00"},
						},
					},
				},
			},
		},
		{
			name: "statuses map onto the Trivy statuses",
			pkg: chainguardosv.Package{
				Ecosystem: "Chainguard",
				Name:      "multi",
				Advisories: []chainguardosv.Advisory{
					{
						ID:       "CGA-0000-0000-0001",
						Upstream: []string{"CVE-2026-4001"},
						Events:   unfixed(),
						Status:   "true_positive_determination",
					},
					{
						ID:       "CGA-0000-0000-0002",
						Upstream: []string{"CVE-2026-4002"},
						Events:   unfixed(),
						Status:   "pending_upstream_fix",
					},
					{
						ID:       "CGA-0000-0000-0003",
						Upstream: []string{"CVE-2026-4003"},
						Events:   unfixed(),
						Status:   "fix_not_planned",
					},
					{
						ID:       "CGA-0000-0000-0004",
						Upstream: []string{"CVE-2026-4004"},
						Events:   unfixed(),
						Status:   "analysis_not_planned",
					},
					{
						ID:       "CGA-0000-0000-0005",
						Upstream: []string{"CVE-2026-4005"},
						Events:   unfixed(),
						Status:   "detection",
					},
					{
						ID:       "CGA-0000-0000-0006",
						Upstream: []string{"CVE-2026-4006"},
						Events:   unfixed(),
						Status:   "something_new_from_chainguard",
					},
					{
						ID:       "CGA-0000-0000-0007",
						Upstream: []string{"CVE-2026-4007"},
						// A record with no events at all cannot be shown to be
						// resolved, so it is treated as affected.
						Events: nil,
						Status: "",
					},
				},
			},
			want: map[string]types.Advisories{
				"CVE-2026-4001": {Entries: []types.Advisory{{Status: types.StatusAffected, VendorIDs: []string{"CGA-0000-0000-0001"}}}},
				"CVE-2026-4002": {Entries: []types.Advisory{{Status: types.StatusFixDeferred, VendorIDs: []string{"CGA-0000-0000-0002"}}}},
				"CVE-2026-4003": {Entries: []types.Advisory{{Status: types.StatusWillNotFix, VendorIDs: []string{"CGA-0000-0000-0003"}}}},
				"CVE-2026-4004": {Entries: []types.Advisory{{Status: types.StatusWillNotFix, VendorIDs: []string{"CGA-0000-0000-0004"}}}},
				"CVE-2026-4005": {Entries: []types.Advisory{{Status: types.StatusUnderInvestigation, VendorIDs: []string{"CGA-0000-0000-0005"}}}},
				"CVE-2026-4006": {Entries: []types.Advisory{{Status: types.StatusAffected, VendorIDs: []string{"CGA-0000-0000-0006"}}}},
				"CVE-2026-4007": {Entries: []types.Advisory{{Status: types.StatusAffected, VendorIDs: []string{"CGA-0000-0000-0007"}}}},
			},
		},
		{
			name: "architectures with the same outcome are merged",
			pkg: chainguardosv.Package{
				Ecosystem: "Chainguard",
				Name:      "openssl",
				Advisories: []chainguardosv.Advisory{
					{
						ID:       "CGA-x86-0000-0000",
						Upstream: []string{"CVE-2026-5000"},
						Arch:     "x86_64",
						Events:   fixed("3.6.2-r0"),
						Status:   "fixed",
					},
					{
						ID:       "CGA-arm-0000-0000",
						Upstream: []string{"CVE-2026-5000"},
						Arch:     "aarch64",
						Events:   fixed("3.6.2-r0"),
						Status:   "fixed",
					},
				},
			},
			want: map[string]types.Advisories{
				"CVE-2026-5000": {
					FixedVersion: "3.6.2-r0",
					Entries: []types.Advisory{
						{
							FixedVersion: "3.6.2-r0",
							Arches: []string{
								"aarch64",
								"x86_64",
							},
							VendorIDs: []string{
								"CGA-arm-0000-0000",
								"CGA-x86-0000-0000",
							},
						},
					},
				},
			},
		},
		{
			name: "architectures with different outcomes stay apart",
			pkg: chainguardosv.Package{
				Ecosystem: "Chainguard",
				Name:      "openssl",
				Advisories: []chainguardosv.Advisory{
					{
						ID:       "CGA-x86-0000-0000",
						Upstream: []string{"CVE-2026-6000"},
						Arch:     "x86_64",
						Events:   fixed("3.6.2-r0"),
						Status:   "fixed",
					},
					{
						ID:       "CGA-arm-0000-0000",
						Upstream: []string{"CVE-2026-6000"},
						Arch:     "aarch64",
						Events:   unfixed(),
						Status:   "pending_upstream_fix",
					},
				},
			},
			want: map[string]types.Advisories{
				"CVE-2026-6000": {
					// Only the architecture that has a fix reports one.
					FixedVersion: "3.6.2-r0",
					Entries: []types.Advisory{
						{
							Status:    types.StatusFixDeferred,
							Arches:    []string{"aarch64"},
							VendorIDs: []string{"CGA-arm-0000-0000"},
						},
						{
							FixedVersion: "3.6.2-r0",
							Arches:       []string{"x86_64"},
							VendorIDs:    []string{"CGA-x86-0000-0000"},
						},
					},
				},
			},
		},
		{
			name: "an advisory with no architecture applies to all of them",
			pkg: chainguardosv.Package{
				Ecosystem: "Chainguard",
				Name:      "curl",
				Advisories: []chainguardosv.Advisory{
					{
						ID:       "CGA-noarch-000-00",
						Upstream: []string{"CVE-2026-7000"},
						Events:   fixed("8.4.0-r0"),
						Status:   "fixed",
					},
				},
			},
			want: map[string]types.Advisories{
				"CVE-2026-7000": {
					FixedVersion: "8.4.0-r0",
					Entries: []types.Advisory{
						{
							FixedVersion: "8.4.0-r0",
							VendorIDs:    []string{"CGA-noarch-000-00"},
						},
					},
				},
			},
		},
		{
			name: "one advisory covering several CVEs is stored under each",
			pkg: chainguardosv.Package{
				Ecosystem: "Chainguard",
				Name:      "glibc",
				Advisories: []chainguardosv.Advisory{
					{
						ID: "CGA-multi-0000-00",
						Upstream: []string{
							"CVE-2026-8001",
							"CVE-2026-8002",
							"GHSA-aaaa-bbbb-cccc",
							"GO-2026-1234",
						},
						Arch:   "x86_64",
						Events: fixed("2.42-r0"),
						Status: "fixed",
					},
				},
			},
			want: map[string]types.Advisories{
				"CVE-2026-8001": {
					FixedVersion: "2.42-r0",
					Entries: []types.Advisory{
						{
							FixedVersion: "2.42-r0",
							Arches:       []string{"x86_64"},
							VendorIDs:    []string{"CGA-multi-0000-00"},
						},
					},
				},
				"CVE-2026-8002": {
					FixedVersion: "2.42-r0",
					Entries: []types.Advisory{
						{
							FixedVersion: "2.42-r0",
							Arches:       []string{"x86_64"},
							VendorIDs:    []string{"CGA-multi-0000-00"},
						},
					},
				},
			},
		},
		{
			name: "advisories with no CVE ID are skipped",
			pkg: chainguardosv.Package{
				Ecosystem: "Chainguard",
				Name:      "ko",
				Advisories: []chainguardosv.Advisory{
					{
						ID:       "CGA-cxmp-5296-c25p",
						Upstream: []string{"GO-2026-5932"},
						Arch:     "aarch64",
						Events:   unfixed(),
						Status:   "pending_upstream_fix",
					},
					{
						// The feed has published CVE IDs written with
						// non-breaking hyphens, which are not CVE IDs.
						ID:       "CGA-bad0-0000-0000",
						Upstream: []string{"CVE‑2026‑55200"},
						Arch:     "aarch64",
						Events:   unfixed(),
						Status:   "detection",
					},
				},
			},
			want: map[string]types.Advisories{},
		},
		{
			// The feed has only ever published ranges that start at "0". A range
			// starting anywhere else cannot be expressed as a single fixed
			// version, so it is reported as affected rather than approximated.
			name: "a range that does not start at the first version is affected",
			pkg: chainguardosv.Package{
				Ecosystem: "Chainguard",
				Name:      "curl",
				Advisories: []chainguardosv.Advisory{
					{
						ID:       "CGA-0000-0000-000c",
						Upstream: []string{"CVE-2026-12000"},
						Arch:     "x86_64",
						Events: []chainguardosv.Event{
							{Introduced: "8.0.0-r0"},
							{Fixed: "8.4.0-r0"},
						},
						Status: "fixed",
					},
				},
			},
			want: map[string]types.Advisories{
				"CVE-2026-12000": {
					Entries: []types.Advisory{
						{
							Status:    types.StatusAffected,
							Arches:    []string{"x86_64"},
							VendorIDs: []string{"CGA-0000-0000-000c"},
						},
					},
				},
			},
		},
		{
			name: "several disjoint ranges are affected",
			pkg: chainguardosv.Package{
				Ecosystem: "Chainguard",
				Name:      "curl",
				Advisories: []chainguardosv.Advisory{
					{
						ID:       "CGA-0000-0000-000d",
						Upstream: []string{"CVE-2026-13000"},
						Arch:     "x86_64",
						Events: []chainguardosv.Event{
							{Introduced: "0"},
							{Fixed: "1.0.0-r0"},
							{Introduced: "0"},
							{Fixed: "3.0.0-r0"},
						},
						Status: "fixed",
					},
				},
			},
			want: map[string]types.Advisories{
				"CVE-2026-13000": {
					Entries: []types.Advisory{
						{
							Status:    types.StatusAffected,
							Arches:    []string{"x86_64"},
							VendorIDs: []string{"CGA-0000-0000-000d"},
						},
					},
				},
			},
		},
		{
			name: "a version that is not an APK version still yields a result",
			pkg: chainguardosv.Package{
				Ecosystem: "Chainguard",
				Name:      "broken",
				Advisories: []chainguardosv.Advisory{
					{
						ID:       "CGA-0000-0000-000a",
						Upstream: []string{"CVE-2026-9000"},
						Arch:     "x86_64",
						Events:   fixed("not a version"),
						Status:   "fixed",
					},
					{
						ID:       "CGA-0000-0000-000b",
						Upstream: []string{"CVE-2026-9000"},
						Arch:     "x86_64",
						Events:   fixed("also not a version"),
						Status:   "fixed",
					},
				},
			},
			want: map[string]types.Advisories{
				"CVE-2026-9000": {
					FixedVersion: "not a version",
					Entries: []types.Advisory{
						{
							FixedVersion: "not a version",
							Arches:       []string{"x86_64"},
							VendorIDs:    []string{"CGA-0000-0000-000a"},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, chainguardosv.Aggregate(tt.pkg))
		})
	}
}
