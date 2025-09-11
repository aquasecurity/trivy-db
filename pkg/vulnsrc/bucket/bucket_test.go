package bucket_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

func TestBucket_Name(t *testing.T) {
	tests := []struct {
		name   string
		bucket bucket.Bucket
		want   string
	}{
		// OS ecosystems
		{
			name:   "Alpine with version",
			bucket: bucket.NewAlpine("3.11"),
			want:   "alpine 3.11",
		},
		{
			name:   "Alpine without version",
			bucket: bucket.NewAlpine(""),
			want:   "alpine",
		},
		{
			name:   "RedHat with version",
			bucket: bucket.NewRedHat("8"),
			want:   "redhat 8",
		},
		// Language ecosystems
		{
			name: "Go with GHSA",
			bucket: bucket.NewGo(types.DataSource{
				ID:   vulnerability.GHSA,
				Name: "GitHub Security Advisory",
				URL:  "https://github.com/advisories",
			}),
			want: "go::GitHub Security Advisory",
		},
		{
			name: "npm with GitLab",
			bucket: bucket.NewNpm(types.DataSource{
				ID:   vulnerability.GLAD,
				Name: "GitLab Advisory Database",
				URL:  "https://gitlab.com/advisories",
			}),
			want: "npm::GitLab Advisory Database",
		},
		{
			name: "PyPI with GHSA",
			bucket: bucket.NewPyPI(types.DataSource{
				ID:   vulnerability.GHSA,
				Name: "GitHub Security Advisory PyPI",
				URL:  "https://github.com/advisories",
			}),
			want: "pip::GitHub Security Advisory PyPI",
		},
		{
			name: "Composer with GHSA",
			bucket: bucket.NewComposer(types.DataSource{
				ID:   vulnerability.GHSA,
				Name: "GitHub Security Advisory Composer",
				URL:  "https://github.com/advisories",
			}),
			want: "composer::GitHub Security Advisory Composer",
		},
		{
			name: "RubyGems with GHSA",
			bucket: bucket.NewRubyGems(types.DataSource{
				ID:   vulnerability.GHSA,
				Name: "GitHub Security Advisory RubyGems",
				URL:  "https://github.com/advisories",
			}),
			want: "rubygems::GitHub Security Advisory RubyGems",
		},
		{
			name: "Cargo with GHSA",
			bucket: bucket.NewCargo(types.DataSource{
				ID:   vulnerability.GHSA,
				Name: "GitHub Security Advisory Cargo",
				URL:  "https://github.com/advisories",
			}),
			want: "cargo::GitHub Security Advisory Cargo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.bucket.Name()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBucket_DataSource(t *testing.T) {
	tests := []struct {
		name   string
		bucket bucket.Bucket
		want   types.DataSource
	}{
		{
			name:   "Alpine OS bucket returns empty DataSource",
			bucket: bucket.NewAlpine("3.11"),
			want:   types.DataSource{},
		},
		{
			name:   "RedHat OS bucket returns empty DataSource",
			bucket: bucket.NewRedHat("8"),
			want:   types.DataSource{},
		},
		{
			name: "Go language bucket returns DataSource",
			bucket: bucket.NewGo(types.DataSource{
				ID:   vulnerability.GHSA,
				Name: "GitHub Security Advisory",
				URL:  "https://github.com/advisories",
			}),
			want: types.DataSource{
				ID:   vulnerability.GHSA,
				Name: "GitHub Security Advisory",
				URL:  "https://github.com/advisories",
			},
		},
		{
			name: "npm language bucket returns DataSource",
			bucket: bucket.NewNpm(types.DataSource{
				ID:   vulnerability.GLAD,
				Name: "GitLab Advisory Database",
				URL:  "https://gitlab.com/advisories",
			}),
			want: types.DataSource{
				ID:   vulnerability.GLAD,
				Name: "GitLab Advisory Database",
				URL:  "https://gitlab.com/advisories",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.bucket.DataSource()
			assert.Equal(t, tt.want, got)
		})
	}
}

