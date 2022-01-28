package db_test

import (
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/stretchr/testify/require"
)

func TestInit(t *testing.T) {
	tests := []struct {
		name   string
		dbPath string
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
			tmpDir, err := ioutil.TempDir("", "test")
			require.NoError(t, err)
			defer os.RemoveAll(tmpDir)

			if tt.dbPath != "" {
				dbPath := db.Path(tmpDir)
				dbDir := filepath.Dir(dbPath)
				err = os.MkdirAll(dbDir, 0700)
				require.NoError(t, err)

				err = copy(dbPath, tt.dbPath)
				require.NoError(t, err)
			}

			err = db.Init(tmpDir)
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
