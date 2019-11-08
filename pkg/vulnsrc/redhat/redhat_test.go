package redhat

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestMain(m *testing.M) {
	utils.Quiet = true
	os.Exit(m.Run())
}

func TestVulnSrc_Update(t *testing.T) {
	testCases := []struct {
		name             string
		cacheDir         string
		batchUpdateErr   error
		expectedErrorMsg string
		expectedVulns    []types.Advisory
	}{
		{
			name:     "happy1: AffectedRelease is an array",
			cacheDir: filepath.Join("testdata", "happy1"),
		},
		{
			name:     "happy2: AffectedRelease is an object",
			cacheDir: filepath.Join("testdata", "happy2"),
		},
		{
			name:     "happy3: PackageState is an array",
			cacheDir: filepath.Join("testdata", "happy3"),
		},
		{
			name:     "happy4: PackageState is an object",
			cacheDir: filepath.Join("testdata", "happy4"),
		},
		{
			name:             "sad1: AffectedRelease is an invalid array",
			cacheDir:         filepath.Join("testdata", "sad1"),
			expectedErrorMsg: "json: cannot unmarshal string into Go struct field RedhatCVEAffectedReleaseArray.affected_release of type redhat.RedhatAffectedRelease",
		},
		{
			name:             "sad2: AffectedRelease is an invalid object",
			cacheDir:         filepath.Join("testdata", "sad2"),
			expectedErrorMsg: "json: cannot unmarshal number into Go struct field RedhatAffectedRelease.affected_release.product_name of type string",
		},
		{
			name:             "sad3: PackageState is an invalid array",
			cacheDir:         filepath.Join("testdata", "sad3"),
			expectedErrorMsg: "json: cannot unmarshal string into Go struct field RedhatCVEPackageStateArray.package_state of type redhat.RedhatPackageState",
		},
		{
			name:             "sad4: PackageState is an invalid object",
			cacheDir:         filepath.Join("testdata", "sad4"),
			expectedErrorMsg: "json: cannot unmarshal number into Go struct field RedhatPackageState.package_state.product_name of type string",
		},
		{
			name:             "sad5: invalid JSON",
			cacheDir:         filepath.Join("testdata", "sad5"),
			expectedErrorMsg: "json: cannot unmarshal string into Go value of type redhat.RedhatCVE",
		},
		{
			name:             "sad6: AffectedRelease is an unknown type",
			cacheDir:         filepath.Join("testdata", "sad6"),
			expectedErrorMsg: "unknown affected_release type",
		},
		{
			name:             "sad7: PackageState is an unknown type",
			cacheDir:         filepath.Join("testdata", "sad7"),
			expectedErrorMsg: "unknown package_state type",
		},
		{
			name:             "cache dir doesnt exist",
			cacheDir:         "badpathdoesnotexist",
			expectedErrorMsg: "lstat badpathdoesnotexist/vuln-list/redhat: no such file or directory",
		},
		{
			name:             "unable to save redhat defintions",
			cacheDir:         filepath.Join("testdata", "happy1"),
			batchUpdateErr:   errors.New("unable to batch update"),
			expectedErrorMsg: "unable to batch update",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockDBConfig := new(db.MockDBConfig)
			mockDBConfig.On("BatchUpdate", mock.Anything).Return(tc.batchUpdateErr)
			ac := VulnSrc{dbc: mockDBConfig}

			err := ac.Update(tc.cacheDir)
			switch {
			case tc.expectedErrorMsg != "":
				assert.Contains(t, err.Error(), tc.expectedErrorMsg, tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}
		})
	}
}
