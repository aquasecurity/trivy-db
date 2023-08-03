package db_test

import (
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestConfig_GetEndOfLifeDates(t *testing.T) {
	tests := []struct {
		name     string
		fixtures []string
		os       string
		want     map[string]time.Time
		wantErr  string
	}{
		{
			name:     "happy path",
			os:       "alpine",
			fixtures: []string{"testdata/fixtures/eol.yaml"},
			want: map[string]time.Time{
				"3.14": time.Date(2023, 5, 1, 23, 59, 59, 0, time.UTC),
				"3.15": time.Date(2023, 11, 1, 23, 59, 59, 0, time.UTC),
				"edge": time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC),
			},
		},
		{
			name:     "missing OS",
			os:       "unknown",
			fixtures: []string{"testdata/fixtures/eol.yaml"},
			wantErr:  `failed to get list of end-of-life dates for "unknown"`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Initialize DB
			dbtest.InitDB(t, test.fixtures)
			defer db.Close()

			dbc := db.Config{}
			got, err := dbc.GetEndOfLifeDates(test.os)

			if test.wantErr != "" {
				assert.NotNil(t, err)
				assert.Contains(t, err.Error(), test.wantErr)
			} else {
				assert.Nil(t, err)
				assert.Equal(t, test.want, got)
			}
		})
	}
}
