package vulnsrctest

import (
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sort"
	"testing"
)

func TestGet(t *testing.T, getFunc func(string, string) ([]types.Advisory, error), fixtures []string, wantValues []types.Advisory, release, pkgName, wantErr string) {
	_ = dbtest.InitDB(t, fixtures)
	defer db.Close()

	got, err := getFunc(release, pkgName)

	if wantErr != "" {
		require.Error(t, err)
		assert.Contains(t, err.Error(), wantErr)
		return
	}

	sort.Slice(got, func(i, j int) bool {
		return got[i].VulnerabilityID < got[j].VulnerabilityID
	})

	assert.NoError(t, err)
	assert.Equal(t, wantValues, got)
}
