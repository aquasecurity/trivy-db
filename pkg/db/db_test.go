package db_test

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
)

func TestInit(t *testing.T) {
	tests := []struct {
		name   string
		dbPath string
		dbOpts *bbolt.Options
	}{
		{
			name:   "normal db",
			dbPath: "testdata/normal.db",
		},
		{
			name:   "broken db",
			dbPath: "testdata/broken.db",
		},
		{
			name:   "no db",
			dbPath: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			if tt.dbPath != "" {
				dbPath := db.Path(tmpDir)
				dbDir := filepath.Dir(dbPath)
				err := os.MkdirAll(dbDir, 0700)
				require.NoError(t, err)

				err = copy(dbPath, tt.dbPath)
				require.NoError(t, err)
			}

			err := db.Init(tmpDir, db.WithBoltOptions(tt.dbOpts))
			require.NoError(t, err)
		})
	}
}

func copy(dstPath, srcPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}

	dst, err := os.Create(dstPath)
	if err != nil {
		return err
	}

	_, err = io.Copy(dst, src)
	return err
}
