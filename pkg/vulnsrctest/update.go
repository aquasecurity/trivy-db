package vulnsrctest

import (
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

type WantValues struct {
	Key   []string
	Value interface{}
}

func TestUpdate(t *testing.T, updateFunc func(string) error, dir string, wantValues []WantValues, wantErr string, noBuckets [][]string) {
	tempDir := t.TempDir()
	dbPath := db.Path(tempDir)

	err := db.Init(tempDir)
	require.NoError(t, err)
	defer db.Close()

	err = updateFunc(dir)
	if wantErr != "" {
		require.NotNil(t, err)
		assert.Contains(t, err.Error(), wantErr)
		return
	}

	require.NoError(t, err)
	require.NoError(t, db.Close()) // Need to close before dbtest.JSONEq is called
	for _, want := range wantValues {
		dbtest.JSONEq(t, dbPath, want.Key, want.Value, want.Key)
	}

	for _, noBucket := range noBuckets {
		dbtest.NoBucket(t, dbPath, noBucket, noBucket)
	}
}
