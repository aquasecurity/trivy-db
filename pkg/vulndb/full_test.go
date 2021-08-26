package vulndb_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulndb"
)

func Test_fullDB_Build(t *testing.T) {
	modified := time.Date(2020, 8, 24, 17, 37, 0, 0, time.UTC)
	published := time.Date(2019, 4, 7, 0, 29, 0, 0, time.UTC)

	type wantKV struct {
		key   []string
		value interface{}
	}
	tests := []struct {
		name       string
		fixtures   []string
		wantValues []wantKV
		wantErr    string
	}{
		{
			name: "happy path",
			fixtures: []string{
				"testdata/fixtures/happy/severity.yaml",
				"testdata/fixtures/happy/vulnerability-detail.yaml",
				"testdata/fixtures/happy/advisory-detail.yaml",
			},
			wantValues: []wantKV{
				{
					key: []string{"Red Hat Enterprise Linux 8", "python-jinja2", "CVE-2019-10906"},
					value: types.Advisory{
						FixedVersion: "2.10.1-2.el8_0",
					},
				},
				{
					key: []string{"vulnerability", "CVE-2019-10906"},
					value: types.Vulnerability{
						Title:       "python-jinja2: str.format_map allows sandbox escape",
						Description: "In Pallets Jinja before 2.10.1, str.format_map allows a sandbox escape.",
						Severity:    "HIGH",
						VendorSeverity: map[string]types.Severity{
							"nvd":    types.SeverityHigh,
							"redhat": types.SeverityCritical,
						},
						PublishedDate:    &published,
						LastModifiedDate: &modified,
					},
				},
			},
		},
		{
			name: "broken advisory detail",
			fixtures: []string{
				"testdata/fixtures/happy/severity.yaml",
				"testdata/fixtures/happy/vulnerability-detail.yaml",
				"testdata/fixtures/sad/advisory-detail.yaml",
			},
			wantErr: "failed to unmarshall advisory_detail",
		},
		{
			name: "broken severity",
			fixtures: []string{
				"testdata/fixtures/sad/severity.yaml",
				"testdata/fixtures/happy/vulnerability-detail.yaml",
				"testdata/fixtures/happy/advisory-detail.yaml",
			},
			wantErr: "unknown severity: BROKEN",
		},
		{
			name: "missing advisory detail",
			fixtures: []string{
				"testdata/fixtures/happy/severity.yaml",
				"testdata/fixtures/happy/vulnerability-detail.yaml",
			},
			wantErr: "failed to delete advisory detail bucket",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cacheDir := dbtest.InitTestDB(t, tt.fixtures)
			defer db.Close()

			full := vulndb.New(db.TypeFull, cacheDir, 12*time.Hour)
			err := full.Build(nil)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)

			// Compare DB entries
			require.NoError(t, db.Close())
			dbPath := db.Path(cacheDir)
			for _, want := range tt.wantValues {
				dbtest.JSONEq(t, dbPath, want.key, want.value)
			}

			// Ensure that temporal buckets are removed
			dbtest.NoBucket(t, dbPath, []string{"advisory-detail"})
			dbtest.NoBucket(t, dbPath, []string{"vulnerability-detail"})
			dbtest.NoBucket(t, dbPath, []string{"severity"})
		})
	}
}
