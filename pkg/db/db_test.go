package db_test

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
)

func TestInit(t *testing.T) {
	tests := []struct {
		name    string
		dbPath  string
		wantErr string
		opts    []db.Option
	}{
		{
			name:   "normal db",
			dbPath: "testdata/normal.db",
		},
		{
			name:    "broken db",
			dbPath:  "testdata/broken.db",
			wantErr: "db corrupted",
		},
		{
			name:   "no db",
			dbPath: "",
		},
		{
			name:   "read-only mode with existing db",
			dbPath: "testdata/normal.db",
			opts:   []db.Option{db.WithBoltOptions(&bolt.Options{ReadOnly: true})},
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

			err := db.Init(tmpDir, tt.opts...)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			t.Cleanup(func() {
				_ = db.Close()
			})
		})
	}
}

func TestMultipleInit(t *testing.T) {
	tests := []struct {
		name       string
		opts       []db.Option
		assertFunc require.ErrorAssertionFunc
	}{
		{
			name:       "without read-only option should fail",
			opts:       nil,
			assertFunc: require.Error,
		},
		{
			name:       "with read-only option should succeed",
			opts:       []db.Option{db.WithBoltOptions(&bolt.Options{ReadOnly: true})},
			assertFunc: require.NoError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			// Prepare database file
			dbPath := db.Path(tmpDir)
			dbDir := filepath.Dir(dbPath)
			err := os.MkdirAll(dbDir, 0o700)
			require.NoError(t, err)

			err = copyFile(dbPath, "testdata/normal.db")
			require.NoError(t, err)

			// First Init
			err = db.Init(tmpDir, tt.opts...)
			require.NoError(t, err)

			// Save the first connection before it gets overwritten
			dbc := db.Config{}
			firstConn := dbc.Connection()
			t.Cleanup(func() {
				if firstConn != nil {
					_ = firstConn.Close()
				}
			})

			// Second Init without closing
			err = db.Init(tmpDir, tt.opts...)
			tt.assertFunc(t, err)

			// If second Init succeeded, close the second connection too
			if err == nil {
				t.Cleanup(func() {
					_ = db.Close()
				})
			}
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
