package bucket_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

func TestBucketName(t *testing.T) {
	testCases := []struct {
		name       string
		ecosystem  types.Ecosystem
		dataSource string
		want       string
		wantErr    string
	}{
		{
			name:       "go",
			ecosystem:  vulnerability.Go,
			dataSource: "GitLab Advisory Database",
			want:       "go::GitLab Advisory Database",
		},
		{
			name:       "rubygems",
			ecosystem:  vulnerability.RubyGems,
			dataSource: "GitHub Advisory Database",
			want:       "rubygems::GitHub Advisory Database",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := bucket.Name(tc.ecosystem, tc.dataSource)
			assert.Equal(t, tc.want, got)
		})
	}
}
