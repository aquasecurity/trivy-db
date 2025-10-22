package rootio

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
)

func TestNewBucket(t *testing.T) {
	tests := []struct {
		name       string
		ecosystem  ecosystem.Type
		version    string
		wantName   string
		wantErrMsg string
	}{
		// OS ecosystems
		{
			name:      "Alpine OS",
			ecosystem: ecosystem.Alpine,
			version:   "3.18",
			wantName:  "root.io alpine 3.18",
		},
		{
			name:      "Debian OS",
			ecosystem: ecosystem.Debian,
			version:   "12",
			wantName:  "root.io debian 12",
		},
		{
			name:      "Ubuntu OS",
			ecosystem: ecosystem.Ubuntu,
			version:   "22.04",
			wantName:  "root.io ubuntu 22.04",
		},
		// Language ecosystems - should use standard bucket format
		{
			name:      "NPM ecosystem",
			ecosystem: ecosystem.Npm,
			version:   "",
			wantName:  "npm::Root.io Security Patches",
		},
		{
			name:      "PyPI ecosystem",
			ecosystem: ecosystem.Pip,
			version:   "",
			wantName:  "pip::Root.io Security Patches",
		},
		{
			name:      "RubyGems ecosystem",
			ecosystem: ecosystem.RubyGems,
			version:   "",
			wantName:  "rubygems::Root.io Security Patches",
		},
		{
			name:      "Maven ecosystem",
			ecosystem: ecosystem.Maven,
			version:   "",
			wantName:  "maven::Root.io Security Patches",
		},
		{
			name:      "Go ecosystem",
			ecosystem: ecosystem.Go,
			version:   "",
			wantName:  "go::Root.io Security Patches",
		},
		{
			name:      "NuGet ecosystem",
			ecosystem: ecosystem.NuGet,
			version:   "",
			wantName:  "nuget::Root.io Security Patches",
		},
		{
			name:      "Cargo ecosystem",
			ecosystem: ecosystem.Cargo,
			version:   "",
			wantName:  "cargo::Root.io Security Patches",
		},
		// Unsupported ecosystem
		{
			name:       "Unsupported ecosystem",
			ecosystem:  ecosystem.Cocoapods,
			version:    "",
			wantErrMsg: "unsupported base ecosystem for Root.io bucket",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bkt, err := newBucket(tt.ecosystem, tt.version)

			if tt.wantErrMsg != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrMsg)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantName, bkt.Name())
			assert.Equal(t, tt.ecosystem, bkt.Ecosystem())
		})
	}
}
