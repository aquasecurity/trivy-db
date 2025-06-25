package rootio

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

func TestVulnSrc_Update(t *testing.T) {
	tests := []struct {
		name      string
		dir       string
		baseOS    OSType
		wantError bool
	}{
		{
			name:      "happy path debian",
			dir:       filepath.Join("testdata", "happy"),
			baseOS:    Debian,
			wantError: false,
		},
		{
			name:      "happy path ubuntu",
			dir:       filepath.Join("testdata", "happy"),
			baseOS:    Ubuntu,
			wantError: false,
		},
		{
			name:      "happy path alpine",
			dir:       filepath.Join("testdata", "happy"),
			baseOS:    Alpine,
			wantError: false,
		},
		{
			name:      "sad path - invalid JSON",
			dir:       filepath.Join("testdata", "sad"),
			baseOS:    Debian,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			_ = db.Init(tempDir)
			defer db.Close()

			vs := NewVulnSrc(tt.baseOS)

			err := vs.Update(tt.dir)
			if tt.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestVulnSrc_Get(t *testing.T) {
	tempDir := t.TempDir()
	_ = db.Init(tempDir)
	defer db.Close()

	vs := NewVulnSrc(Debian)

	// Test that Get doesn't crash - actual functionality would require DB setup
	advisories, err := vs.Get("11", "openssl")
	require.NoError(t, err)
	assert.Len(t, advisories, 0) // Empty result is expected with no DB data
}

func TestIsValidOSType(t *testing.T) {
	tests := []struct {
		osType string
		want   bool
	}{
		{
			osType: "debian",
			want:   true,
		},
		{
			osType: "ubuntu",
			want:   true,
		},
		{
			osType: "alpine",
			want:   true,
		},
		{
			osType: "centos",
			want:   false,
		},
		{
			osType: "fedora",
			want:   false,
		},
		{
			osType: "",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.osType, func(t *testing.T) {
			got := IsValidOSType(tt.osType)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestVulnSrc_Name(t *testing.T) {
	vs := NewVulnSrc(Debian)
	assert.Equal(t, vulnerability.RootIO, vs.Name())
}
