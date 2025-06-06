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
		name    string
		dbPath  string
		wantErr string
		dbOpts  *bbolt.Options
	}{
		{
			name:   "normal db",
			dbPath: "testdata/normal.db",
		},
		{
			name:    "broken db",
			dbPath:  "testdata/broken.db",
			wantErr: "invalid memory address or nil pointer dereference",
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
				err := os.MkdirAll(dbDir, 0o700)
				require.NoError(t, err)

				err = copyFile(dbPath, tt.dbPath)
				require.NoError(t, err)
			}

			err := db.Init(tmpDir, db.WithBoltOptions(tt.dbOpts))
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
		})
	}
}

func copyFile(dstPath, srcPath string) error {
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
