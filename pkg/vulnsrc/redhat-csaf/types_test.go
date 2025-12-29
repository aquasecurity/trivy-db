package redhatcsaf

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-db/pkg/types"
)

func TestEntries_Less(t *testing.T) {
	entries := Entries{
		{
			FixedVersion: "1.0.0",
			Status:       types.StatusFixed,
			CVEs: []CVEEntry{
				{ID: "CVE-2024-0001"},
			},
			Arches:             []string{"x86_64"},
			AffectedCPEIndices: []int{0},
		},
		{
			FixedVersion: "2.0.0",
			Status:       types.StatusAffected,
			CVEs: []CVEEntry{
				{ID: "CVE-2024-0002"},
			},
			Arches:             []string{"aarch64"},
			AffectedCPEIndices: []int{1},
		},
	}

	assert.True(t, entries.Less(0, 1))
}

func TestEntries_Swap(t *testing.T) {
	entries := Entries{
		{FixedVersion: "1.0.0"},
		{FixedVersion: "2.0.0"},
	}

	entries.Swap(0, 1)
	assert.Equal(t, "2.0.0", entries[0].FixedVersion)
	assert.Equal(t, "1.0.0", entries[1].FixedVersion)
}

func TestEntries_Len(t *testing.T) {
	entries := Entries{
		{FixedVersion: "1.0.0"},
		{FixedVersion: "2.0.0"},
	}

	assert.Equal(t, 2, entries.Len())
}
