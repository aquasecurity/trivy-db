package bucket_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
)

func TestBucketName(t *testing.T) {
	testCases := []struct {
		name       string
		ecosystem  string
		dataSource string
		want       string
		wantErr    string
	}{
		{
			name:       "happy path go",
			ecosystem:  "go",
			dataSource: "GitLab Advisory Database",
			want:       "go::GitLab Advisory Database",
		},
		{
			name:       "happy path golang",
			ecosystem:  "golang",
			dataSource: "GitLab Advisory Database",
			want:       "go::GitLab Advisory Database",
		},
		{
			name:       "happy path maven",
			ecosystem:  "maven",
			dataSource: "GitLab Advisory Database",
			want:       "maven::GitLab Advisory Database",
		},
		{
			name:       "sad path unknown",
			ecosystem:  "unknown",
			dataSource: "GitLab Advisory Database",
			wantErr:    "unknown ecosystem",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := bucket.Name(tc.ecosystem, tc.dataSource)
			assert.Equal(t, tc.want, got)
		})
	}
}
