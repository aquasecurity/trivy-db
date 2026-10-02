package osv

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A range's events should start with an "introduced" event, but some feeds ship
// malformed ranges that start with a "fixed" or "last_affected" event. Make sure
// the parser handles those without panicking on an out-of-range index.
func TestParseAffectedVersions_LeadingFixedEvent(t *testing.T) {
	tests := []struct {
		name           string
		affected       Affected
		wantVulnerable []string
		wantPatched    []string
	}{
		{
			name: "range starts with a fixed event",
			affected: Affected{
				Package: Package{Ecosystem: "npm", Name: "example"},
				Ranges: []Range{
					{
						Type: "ECOSYSTEM",
						Events: []RangeEvent{
							{Fixed: "1.2.5"},
						},
					},
				},
			},
			wantVulnerable: []string{"<1.2.5"},
			wantPatched:    []string{"1.2.5"},
		},
		{
			name: "range starts with a last_affected event",
			affected: Affected{
				Package: Package{Ecosystem: "npm", Name: "example"},
				Ranges: []Range{
					{
						Type: "ECOSYSTEM",
						Events: []RangeEvent{
							{LastAffected: "2.0.0"},
						},
					},
				},
			},
			wantVulnerable: []string{"<=2.0.0"},
			wantPatched:    nil,
		},
		{
			name: "fixed-first range following a complete range keeps both ranges",
			affected: Affected{
				Package: Package{Ecosystem: "npm", Name: "example"},
				Ranges: []Range{
					{
						Type: "ECOSYSTEM",
						Events: []RangeEvent{
							{Introduced: "1.0.0"},
							{Fixed: "1.5.0"},
						},
					},
					{
						Type: "ECOSYSTEM",
						Events: []RangeEvent{
							{Fixed: "2.0.0"},
						},
					},
				},
			},
			wantVulnerable: []string{">=1.0.0, <1.5.0", "<2.0.0"},
			wantPatched:    []string{"1.5.0", "2.0.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vulnerable, patched, err := parseAffectedVersions(tt.affected)
			require.NoError(t, err)
			assert.Equal(t, tt.wantVulnerable, vulnerable)
			assert.Equal(t, tt.wantPatched, patched)
		})
	}
}
