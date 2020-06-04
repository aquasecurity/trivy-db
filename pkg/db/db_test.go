package db_test

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/stretchr/testify/assert"
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

func TestConfig_StoreMetadata(t *testing.T) {
	d, _ := ioutil.TempDir("", "TestConfig_StoreMetadata_*")
	defer func() {
		os.RemoveAll(d)
	}()

	_ = db.Init(d)
	dbc := db.Config{}

	fixedTime := time.Unix(1584149443, 0)
	metadata := db.Metadata{
		Version:    42,
		Type:       db.TypeFull,
		NextUpdate: fixedTime.UTC(),
		UpdatedAt:  fixedTime.UTC(),
	}

	require.NoError(t, dbc.StoreMetadata(metadata, d))
	b, err := ioutil.ReadFile(d + "/metadata.json")
	require.NoError(t, err)
	var got db.Metadata
	_ = json.Unmarshal(b, &got)
	assert.Equal(t, metadata, got)
}

func TestConfig_GetMetadata(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		d, _ := ioutil.TempDir("", "TestConfig_GetMetadata_*")
		defer func() {
			os.RemoveAll(d)
		}()

		_ = db.Init(d)
		dbc := db.Config{}

		fixedTime := time.Unix(1584149443, 0)
		_ = dbc.SetMetadata(db.Metadata{
			Version:    42,
			Type:       db.TypeFull,
			NextUpdate: fixedTime,
			UpdatedAt:  fixedTime,
		})

		md, err := dbc.GetMetadata()
		require.NoError(t, err)
		assert.Equal(t, 42, md.Version)
		assert.Equal(t, db.TypeFull, md.Type)
		assert.Equal(t, time.Unix(1584149443, 0).Unix(), md.NextUpdate.Unix())
		assert.Equal(t, time.Unix(1584149443, 0).Unix(), md.UpdatedAt.Unix())
	})

	t.Run("sad path, no bucket exists", func(t *testing.T) {
		d, _ := ioutil.TempDir("", "TestConfig_GetMetadata_*")
		defer func() {
			os.RemoveAll(d)
		}()

		_ = db.Init(d)
		dbc := db.Config{}

		md, err := dbc.GetMetadata()
		assert.EqualError(t, err, "unexpected end of JSON input")
		b, _ := json.Marshal(md)
		assert.Equal(t, `{"NextUpdate":"0001-01-01T00:00:00Z","UpdatedAt":"0001-01-01T00:00:00Z"}`, string(b))
		assert.Empty(t, md)
	})
}
