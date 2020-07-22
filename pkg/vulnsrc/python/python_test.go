package python

import (
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-db/pkg/types"
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
		expectedAdvisory []types.Advisory
		expectErr bool
	}{
		{
			name: "happy path",
			args: args{
				dir: "testdata/fixtures",
			},
			expectedAdvisory: []types.Advisory {
				{
					VulnerabilityID: "CVE-2018-9986",
				},
				{
					VulnerabilityID: "CVE-2018-9987",
				},
				{
					VulnerabilityID: "CVE-2018-9990",
				},
				{
					VulnerabilityID: "CVE-2018-9999",
				},
				{
					VulnerabilityID: "CVE-2019-18933",
				},
				{
					VulnerabilityID: "CVE-2020-10935",
				},
				{
					VulnerabilityID: "CVE-2020-9444",
				},
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
			sort.Slice(advisories[:], func(i, j int) bool {
				return strings.Compare(advisories[i].VulnerabilityID, advisories[j].VulnerabilityID) <= 0
			})
			assert.True(t, reflect.DeepEqual(tc.expectedAdvisory,advisories), "expected %v for package zulip, got: %v",tc.expectedAdvisory, advisories)
			os.RemoveAll("testdata/db")
		})
	}
}
