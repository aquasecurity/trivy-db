package redhatcsaf

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/types"
)

func TestEntry_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Entry
		wantErr bool
	}{
		{
			name:  "valid entry",
			input: `{"FixedVersion":"1.0.0","Cves":[{"ID":"CVE-2024-9999","Severity":2}],"Arches":["x86_64"],"Status":3,"Affected":[0,1]}`,
			want: Entry{
				FixedVersion: "1.0.0",
				CVEs: []CVEEntry{
					{
						ID:       "CVE-2024-9999",
						Severity: types.SeverityMedium,
					},
				},
				Arches:             []string{"x86_64"},
				Status:             types.StatusFixed,
				AffectedCPEIndices: []int{0, 1},
			},
		},
		{
			name:    "invalid status",
			input:   `{"Status":999}`,
			wantErr: false,
			want:    Entry{Status: types.StatusUnknown},
		},
		{
			name:    "invalid json format",
			input:   `{"Status": "invalid"}`,
			wantErr: true,
		},
		{
			name:    "empty json",
			input:   `{}`,
			wantErr: false,
			want:    Entry{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var entry Entry
			err := json.Unmarshal([]byte(tt.input), &entry)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, entry)
		})
	}
}

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
