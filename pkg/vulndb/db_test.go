package vulndb_test

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"
	"k8s.io/utils/clock"
	fake "k8s.io/utils/clock/testing"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-db/pkg/metadata"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulndb"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

type fakeVulnSrc struct{}

func (f fakeVulnSrc) Name() types.SourceID { return "fake" }

func (f fakeVulnSrc) Update(dir string) error {
	if strings.Contains(dir, "bad") {
		return xerrors.New("something bad")
	}
	return nil
}

func TestTrivyDB_Insert(t *testing.T) {
	type fields struct {
		cacheDir string
		clock    clock.Clock
	}
	type args struct {
		targets []string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    metadata.Metadata
		wantErr string
	}{
		{
			name: "happy path",
			fields: fields{
				cacheDir: "happy",
				clock:    fake.NewFakeClock(time.Date(2021, 1, 2, 3, 4, 5, 0, time.UTC)),
			},
			args: args{
				targets: []string{"fake"},
			},
			want: metadata.Metadata{
				Version:    db.SchemaVersion,
				NextUpdate: time.Date(2021, 1, 2, 15, 4, 5, 0, time.UTC),
				UpdatedAt:  time.Date(2021, 1, 2, 3, 4, 5, 0, time.UTC),
			},
		},
		{
			name: "sad path: unknown source",
			fields: fields{
				cacheDir: "sad",
				clock:    fake.NewFakeClock(time.Date(2021, 1, 2, 3, 4, 5, 0, time.UTC)),
			},
			args: args{
				targets: []string{"unknown"},
			},
			wantErr: "unknown is not supported",
		},
		{
			name: "sad path: update error",
			fields: fields{
				cacheDir: "bad",
				clock:    fake.NewFakeClock(time.Date(2021, 1, 2, 3, 4, 5, 0, time.UTC)),
			},
			args: args{
				targets: []string{"fake"},
			},
			wantErr: "fake update error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vulnsrcs := map[types.SourceID]vulnsrc.VulnSrc{
				"fake": fakeVulnSrc{},
			}
			cacheDir := filepath.Join(t.TempDir(), tt.fields.cacheDir)
			outputDir := t.TempDir()

			require.NoError(t, db.Init(cacheDir))
			defer db.Close()

			c := vulndb.New(cacheDir, outputDir, 12*time.Hour, vulndb.WithClock(tt.fields.clock), vulndb.WithVulnSrcs(vulnsrcs))
			err := c.Insert(tt.args.targets)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)

			// Compare metadata JSON file
			got, err := metadata.NewClient(outputDir).Get()
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestTrivyDB_Build(t *testing.T) {
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
				"testdata/fixtures/happy/vulnid.yaml",
				"testdata/fixtures/happy/vulnerability-detail.yaml",
				"testdata/fixtures/happy/advisory-detail.yaml",
			},
			wantValues: []wantKV{
				{
					key: []string{
						"Red Hat Enterprise Linux 8",
						"python-jinja2",
						"CVE-2019-10906",
					},
					value: types.Advisory{
						FixedVersion: "2.10.1-2.el8_0",
					},
				},
				{
					key: []string{
						"vulnerability",
						"CVE-2019-10906",
					},
					value: types.Vulnerability{
						Title:       "python-jinja2: str.format_map allows sandbox escape",
						Description: "In Pallets Jinja before 2.10.1, str.format_map allows a sandbox escape.",
						Severity:    "HIGH",
						VendorSeverity: map[types.SourceID]types.Severity{
							vulnerability.NVD:    types.SeverityHigh,
							vulnerability.RedHat: types.SeverityCritical,
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
				"testdata/fixtures/happy/vulnid.yaml",
				"testdata/fixtures/happy/vulnerability-detail.yaml",
				"testdata/fixtures/sad/advisory-detail.yaml",
			},
			wantErr: "failed to unmarshall the advisory detail",
		},
		{
			name: "missing advisory detail",
			fixtures: []string{
				"testdata/fixtures/happy/vulnid.yaml",
				"testdata/fixtures/happy/vulnerability-detail.yaml",
			},
			wantErr: "failed to delete advisory detail bucket",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cacheDir := t.TempDir()
			dbDir := dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			full := vulndb.New(cacheDir, dbDir, 12*time.Hour)
			err := full.Build(nil)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)

			// Compare DB entries
			require.NoError(t, db.Close())
			dbPath := db.Path(dbDir)
			for _, want := range tt.wantValues {
				dbtest.JSONEq(t, dbPath, want.key, want.value)
			}

			// Ensure that temporal buckets are removed
			dbtest.NoBucket(t, dbPath, []string{"advisory-detail"})
			dbtest.NoBucket(t, dbPath, []string{"vulnerability-detail"})
			dbtest.NoBucket(t, dbPath, []string{"vulnerability-id"})
		})
	}
}
