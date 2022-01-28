package db_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
)

func TestConfig_GetRedHatCPEs(t *testing.T) {
	tests := []struct {
		name       string
		fixtures   []string
		repository string
		want       []int
		wantErr    string
	}{
		{
			name:       "happy path",
			fixtures:   []string{"testdata/fixtures/redhat-cpe.yaml"},
			repository: "rhel-lb-for-rhel-6-server-eus-debug-rpms",
			want:       []int{1, 2},
		},
		{
			name:       "unknown cpe",
			fixtures:   []string{"testdata/fixtures/redhat-cpe.yaml"},
			repository: "unknown",
			want:       nil,
		},
		{
			name:       "broken value",
			fixtures:   []string{"testdata/fixtures/redhat-cpe.yaml"},
			repository: "broken",
			wantErr:    "JSON unmarshal error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize DB for testing
			dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			dbc := db.Config{}
			got, err := dbc.RedHatRepoToCPEs(tt.repository)

			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)

			// Compare
			assert.Equal(t, tt.want, got)
		})
	}
}
