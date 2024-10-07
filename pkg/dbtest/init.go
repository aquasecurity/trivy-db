package dbtest

import (
	"testing"

	"github.com/stretchr/testify/require"

	fixtures "github.com/aquasecurity/bolt-fixtures"
	"github.com/aquasecurity/trivy-db/pkg/db"
)

func InitDB(t *testing.T, fixtureFiles []string) string {
	t.Helper()

	// Create a temp dir
	dbDir := t.TempDir()
	dbPath := db.Path(dbDir)

	// Load testdata into BoltDB
	loader, err := fixtures.New(dbPath, fixtureFiles)
	require.NoError(t, err)
	require.NoError(t, loader.Load())
	require.NoError(t, loader.Close())

	// Initialize DB
	require.NoError(t, db.Init(dbDir))

	return dbDir
}
