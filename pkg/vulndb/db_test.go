package vulndb_test

import (
	"encoding/json"
	"os"
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
	"github.com/aquasecurity/trivy-db/pkg/vulndb"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc"
)

type fakeVulnSrc struct{}

func (f fakeVulnSrc) Name() string { return "fake" }

func (f fakeVulnSrc) Update(dir string) error {
	if strings.Contains(dir, "bad") {
		return xerrors.New("something bad")
	}
	return nil
}

func TestCore_Insert(t *testing.T) {
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
		want    db.Metadata
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
			want: db.Metadata{
				Version:    db.SchemaVersion,
				Type:       db.TypeFull,
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
			vulnsrcs := map[string]vulnsrc.VulnSrc{
				"fake": fakeVulnSrc{},
			}
			cacheDir := filepath.Join(t.TempDir(), tt.fields.cacheDir)

			require.NoError(t, db.Init(cacheDir))
			defer db.Close()

			c := vulndb.NewCore(cacheDir, 12*time.Hour, vulndb.WithClock(tt.fields.clock), vulndb.WithVulnSrcs(vulnsrcs))
			err := c.Insert(db.TypeFull, tt.args.targets)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)

			f, err := os.Open(filepath.Join(cacheDir, "db", "metadata.json"))
			require.NoError(t, err)

			// Compare metadata JSON file
			var got db.Metadata
			err = json.NewDecoder(f).Decode(&got)
			require.NoError(t, err)

			assert.Equal(t, tt.want, got)

			// Compare DB entries
			require.NoError(t, db.Close())
			dbPath := db.Path(cacheDir)
			dbtest.JSONEq(t, dbPath, []string{"trivy", "metadata", "data"}, tt.want)
		})
	}
}
