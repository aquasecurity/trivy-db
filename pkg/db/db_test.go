package db_test

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
