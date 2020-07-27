package python

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-db/pkg/db"
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
		expectedAdvisory []Advisory
		expectErr bool
	}{
		{
			name: "happy path",
			args: args{
				dir: "testdata/fixtures",
			},
			expectedAdvisory: []Advisory {
				{
					VulnerabilityID: "CVE-2018-9986",
					Specs: []string{"<1.7.2"},
				},
				{
					VulnerabilityID: "CVE-2018-9987",
					Specs: []string{"<1.7.2"},
				},
				{
					VulnerabilityID: "CVE-2018-9990",
					Specs: []string{"<1.7.2"},
				},
				{
					VulnerabilityID: "CVE-2018-9999",
					Specs: []string{"<1.7.2"},
				},
				{
					VulnerabilityID: "CVE-2019-18933",
					Specs: []string{"<2.0.7"},
				},
				{
					VulnerabilityID: "CVE-2020-10935",
					Specs: []string{"<2.1.3"},
				},
				{
					VulnerabilityID: "CVE-2020-9444",
					Specs: []string{"<2.1.3"},
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
			advisories, err := vulSec.Get( "zulip")
			assert.NoError(t, err, tc.name)
			sort.Slice(advisories[:], func(i, j int) bool {
				return strings.Compare(advisories[i].VulnerabilityID, advisories[j].VulnerabilityID) <= 0
			})
			assert.Equal(t, tc.expectedAdvisory,advisories, "expected %v for package zulip, got: %v",tc.expectedAdvisory, advisories)
			os.RemoveAll("testdata/db")
		})
	}
}
