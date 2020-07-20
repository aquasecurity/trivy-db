package python

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

func TestVulnSrc_Update(t *testing.T) {
	type args struct {
		dir string
	}
	testCases := []struct {
		name string
		args struct {
			dir string
		}
		expectErr bool
	}{
		{
			name: "happy path",
			args: args{
				dir: "testdata/fixtures",
			},
			expectErr: false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			db.Init("testdata")
			vulSec := NewVulnSrc()
			err := vulSec.Update(tc.args.dir)
			assert.NoError(t, err, tc.name)
			advisories, err := vulSec.dbc.GetAdvisories(vulnerability.PythonSafetyDB, "zulip")
			assert.NoError(t, err, tc.name)
			assert.Equal(t, 7, len(advisories), "expected 7 advisories for zulip found: %v", len(advisories))
			os.RemoveAll("testdata/db")
		})
	}
}
