package rapidfort

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

// TestNewBucket pins the platform name and BaseID for every base ecosystem
// RapidFort dispatches to. The names are the keys Trivy queries at scan time, so
// a change here silently stops matching; keep this aligned with
// trivy/pkg/detector/ospkg/rapidfort.
func TestNewBucket(t *testing.T) {
	tests := []struct {
		name       string
		ecosystem  ecosystem.Type
		version    string
		wantName   string
		wantBaseID types.SourceID
	}{
		{
			name:       "ubuntu",
			ecosystem:  ecosystem.Ubuntu,
			version:    "20.04",
			wantName:   "rapidfort ubuntu 20.04",
			wantBaseID: vulnerability.Ubuntu,
		},
		{
			name:       "debian",
			ecosystem:  ecosystem.Debian,
			version:    "12",
			wantName:   "rapidfort debian 12",
			wantBaseID: vulnerability.Debian,
		},
		{
			name:       "alpine",
			ecosystem:  ecosystem.Alpine,
			version:    "3.20",
			wantName:   "rapidfort alpine 3.20",
			wantBaseID: vulnerability.Alpine,
		},
		{
			name:       "red hat",
			ecosystem:  ecosystem.RedHat,
			version:    "9",
			wantName:   "rapidfort Red Hat 9",
			wantBaseID: vulnerability.RedHat,
		},
		{
			name:       "oracle linux",
			ecosystem:  ecosystem.OracleLinux,
			version:    "9",
			wantName:   "rapidfort Oracle Linux 9",
			wantBaseID: vulnerability.OracleOVAL,
		},
		{
			name:       "rocky linux",
			ecosystem:  ecosystem.Rocky,
			version:    "9",
			wantName:   "rapidfort rocky 9",
			wantBaseID: vulnerability.Rocky,
		},
		{
			name:       "almalinux",
			ecosystem:  ecosystem.AlmaLinux,
			version:    "9",
			wantName:   "rapidfort alma 9",
			wantBaseID: vulnerability.Alma,
		},
		{
			name:       "amazon linux",
			ecosystem:  ecosystem.AmazonLinux,
			version:    "2023",
			wantName:   "rapidfort amazon linux 2023",
			wantBaseID: vulnerability.Amazon,
		},
		{
			name:       "fedora",
			ecosystem:  ecosystem.Fedora,
			version:    "42",
			wantName:   "rapidfort fedora 42",
			wantBaseID: vulnerability.Fedora,
		},
		// RapidFort's own rebuilds belong to no upstream release, so they keep
		// the feed's ecosystem and drop the version. Every feed therefore gets
		// its own rebuild bucket: an RPM range must never land where the dpkg
		// comparator would read it, and two feeds describing the same rebuild
		// with differing ranges must not overwrite each other.
		{
			name:       "rebuild - ubuntu feed",
			ecosystem:  ecosystem.Ubuntu,
			wantName:   "rapidfort ubuntu",
			wantBaseID: vulnerability.Ubuntu,
		},
		{
			name:       "rebuild - debian feed",
			ecosystem:  ecosystem.Debian,
			wantName:   "rapidfort debian",
			wantBaseID: vulnerability.Debian,
		},
		{
			name:       "rebuild - redhat feed",
			ecosystem:  ecosystem.RedHat,
			wantName:   "rapidfort Red Hat",
			wantBaseID: vulnerability.RedHat,
		},
		// Oracle and Amazon append the version unconditionally, so their
		// version-less names must not keep a trailing space (see Name).
		{
			name:       "rebuild - oracle feed",
			ecosystem:  ecosystem.OracleLinux,
			wantName:   "rapidfort Oracle Linux",
			wantBaseID: vulnerability.OracleOVAL,
		},
		{
			name:       "rebuild - amazon feed",
			ecosystem:  ecosystem.AmazonLinux,
			wantName:   "rapidfort amazon linux",
			wantBaseID: vulnerability.Amazon,
		},
		{
			name:       "rebuild - rocky feed",
			ecosystem:  ecosystem.Rocky,
			wantName:   "rapidfort rocky",
			wantBaseID: vulnerability.Rocky,
		},
		{
			name:       "rebuild - alma feed",
			ecosystem:  ecosystem.AlmaLinux,
			wantName:   "rapidfort alma",
			wantBaseID: vulnerability.Alma,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newBucket(tt.ecosystem, tt.version)
			require.NoError(t, err)
			assert.Equal(t, tt.wantName, got.Name())
			assert.Equal(t, tt.ecosystem, got.Ecosystem())
			assert.Equal(t, tt.wantBaseID, got.DataSource().BaseID)
			assert.Equal(t, vulnerability.RapidFort, got.DataSource().ID)
		})
	}
}

// TestNewBucket_DistinctRebuildBuckets asserts no two feeds share a rebuild
// bucket. Sharing one would let the later file in the walk overwrite the
// earlier, and a bucket reached from feeds of both package formats would be read
// by the wrong comparator.
func TestNewBucket_DistinctRebuildBuckets(t *testing.T) {
	feeds := []ecosystem.Type{
		ecosystem.Ubuntu,
		ecosystem.Debian,
		ecosystem.RedHat,
		ecosystem.OracleLinux,
		ecosystem.Rocky,
		ecosystem.AlmaLinux,
		ecosystem.AmazonLinux,
	}

	seen := make(map[string]ecosystem.Type, len(feeds))
	for _, feed := range feeds {
		t.Run(string(feed), func(t *testing.T) {
			b, err := newBucket(feed, "")
			require.NoError(t, err)

			name := b.Name()
			assert.NotEqual(t, "rapidfort", name, "rebuild bucket must name its feed")
			assert.Equal(t, name, strings.TrimSpace(name), "platform name must not be padded")

			prev, dup := seen[name]
			assert.False(t, dup, "%s shares the %q bucket with %s", feed, name, prev)
			seen[name] = feed
		})
	}
}

// TestNewBucket_UnsupportedEcosystem covers the default branch: an OS RapidFort
// does not curate is rejected so parse skips the whole file.
func TestNewBucket_UnsupportedEcosystem(t *testing.T) {
	for _, eco := range []ecosystem.Type{
		ecosystem.PhotonOS,
		ecosystem.Wolfi,
		ecosystem.Chainguard,
		ecosystem.Type("nonexistent"),
	} {
		t.Run(string(eco), func(t *testing.T) {
			got, err := newBucket(eco, "1")
			require.Error(t, err)
			assert.Nil(t, got)
			assert.Contains(t, err.Error(), "unsupported base ecosystem")
		})
	}
}
