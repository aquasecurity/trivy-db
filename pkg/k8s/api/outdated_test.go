package api_test

import (
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/k8s/api"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestK8sSrc_Update_Get(t *testing.T) {
	tests := []struct {
		name            string
		dir             string
		outDatedAPIData types.OutDatedAPIData
		expectError     bool
	}{
		{
			name: "happy path",
			dir:  filepath.Join("testdata", "happy"),
			outDatedAPIData: types.OutDatedAPIData{"admission.k8s.io/v1beta1": {"AdmissionReview": {
				"deprecation_version": "v1.19",
				"ref":                 "https://github.com/kubernetes/kubernetes/tree/master/staging/src/k8s.io/api/admission/v1beta1/zz_generated.prerelease-lifecycle.go",
				"removed_version":     "v1.22",
				"replacement_version": "admission.k8s.io.v1.AdmissionReview",
			},
			},
			},
			expectError: false,
		},
		{
			name:        "sad path",
			dir:         filepath.Join("testdata", "sad"),
			expectError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db.Init(tt.dir)
			defer os.RemoveAll(filepath.Join(tt.dir, "db"))
			vs := api.NewOutdated()
			err := vs.Update(tt.dir)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				ot, err := vs.Get()
				assert.NoError(t, err)
				assert.True(t, reflect.DeepEqual(ot, tt.outDatedAPIData))
			}
		})
	}
}
