package override_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/override"
)

func TestLoad(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		overridesDir string
		wantCount    int
		wantErr      bool
	}{
		{
			name:         "valid config",
			overridesDir: "testdata",
			wantCount:    3,
			wantErr:      false,
		},
		{
			name:         "non-existent directory",
			overridesDir: "non-existent",
			wantCount:    0,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			patches, err := override.Load(tt.overridesDir)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantCount, patches.Count())
		})
	}
}

func TestPatches_MatchAndApply(t *testing.T) {
	t.Parallel()

	patches, err := override.Load("testdata")
	require.NoError(t, err)

	tests := []struct {
		name       string
		path       string
		original   string
		wantMatch  bool
		wantDelete bool
		wantJSON   string
	}{
		{
			name:       "exact path match - add alias",
			path:       "/ghsa/2025/11/GHSA-xxxx-yyyy-zzzz.json",
			original:   `{"id":"GHSA-xxxx-yyyy-zzzz","aliases":[]}`,
			wantMatch:  true,
			wantDelete: false,
			wantJSON:   `{"aliases":["GHSA-xxxx-yyyy-zzzz","CVE-2024-12345"],"id":"GHSA-xxxx-yyyy-zzzz"}`,
		},
		{
			name:       "path with prefix",
			path:       "/some/cache/dir/ghsa/2025/11/GHSA-xxxx-yyyy-zzzz.json",
			original:   `{"id":"GHSA-xxxx-yyyy-zzzz","aliases":[]}`,
			wantMatch:  true,
			wantDelete: false,
			wantJSON:   `{"aliases":["GHSA-xxxx-yyyy-zzzz","CVE-2024-12345"],"id":"GHSA-xxxx-yyyy-zzzz"}`,
		},
		{
			name:       "no match",
			path:       "/ghsa/2025/11/GHSA-other.json",
			original:   `{"id":"test"}`,
			wantMatch:  false,
			wantDelete: false,
		},
		{
			name:       "delete entry",
			path:       "/ghsa/2025/01/GHSA-delete-me.json",
			original:   `{"id":"GHSA-delete-me","aliases":[]}`,
			wantMatch:  true,
			wantDelete: true,
		},
		{
			name:       "partial filename should not match",
			path:       "/some-GHSA-xxxx-yyyy-zzzz.json",
			original:   `{"id":"test"}`,
			wantMatch:  false,
			wantDelete: false,
		},
		{
			name:       "partial directory should not match",
			path:       "/myghsa/2025/11/GHSA-xxxx-yyyy-zzzz.json",
			original:   `{"id":"test"}`,
			wantMatch:  false,
			wantDelete: false,
		},
		{
			name:       "add references",
			path:       "/osv/go/stdlib/CVE-2024-1234.json",
			original:   `{"id":"CVE-2024-1234"}`,
			wantMatch:  true,
			wantDelete: false,
			wantJSON:   `{"id":"CVE-2024-1234","references":[{"type":"ADVISORY","url":"https://nvd.nist.gov/vuln/detail/CVE-2024-1234"},{"type":"WEB","url":"https://example.invalid/advisory"}]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			patch, ok, err := patches.Match(tt.path)
			require.NoError(t, err)

			if !tt.wantMatch {
				assert.False(t, ok, "expected no match for path %s", tt.path)
				return
			}

			require.True(t, ok, "expected match for path %s", tt.path)
			require.NotNil(t, patch)

			got, err := patch.Apply([]byte(tt.original))
			require.NoError(t, err)

			if tt.wantDelete {
				assert.Empty(t, got, "expected empty result (delete) for path %s", tt.path)
				return
			}

			assert.JSONEq(t, tt.wantJSON, string(got))
		})
	}
}

func TestPatches_NilSafe(t *testing.T) {
	t.Parallel()

	var patches *override.Patches

	// Should not panic
	patch, ok, err := patches.Match("any/path")
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Nil(t, patch)
	assert.Equal(t, 0, patches.Count())
}
