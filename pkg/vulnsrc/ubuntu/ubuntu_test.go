package ubuntu_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/ubuntu"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
)

func TestVulnSrc_Update(t *testing.T) {
	tests := []struct {
		name       string
		dir        string
		wantValues []vulnsrctest.WantValues
		noBuckets  [][]string
		wantErr    string
	}{
		{
			name: "happy path",
			dir:  "testdata",
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"data-source", "ubuntu 18.04"},
					Value: types.DataSource{
						ID:   vulnerability.Ubuntu,
						Name: "Ubuntu CVE Tracker",
						URL:  "https://git.launchpad.net/ubuntu-cve-tracker",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2020-1234", "ubuntu 18.04", "xen"},
					Value: types.Advisory{
						FixedVersion: "1.2.3",
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2020-1234", "ubuntu"},
					Value: types.VulnerabilityDetail{
						Description: "Observable response discrepancy in some Intel(R) Processors may allow an authorized user to potentially enable information disclosure via local access.",
						Severity:    2,
						References:  []string{"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-0089"},
					},
				},
			},
			noBuckets: [][]string{
				{"advisory-detail", "CVE-2020-1234", "ubuntu 20.04"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := ubuntu.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
			})
		})
	}
}

func TestUbuntuStatusFromStatus(t *testing.T) {
	tests := []struct {
		name     string
		status   string
		expected types.Status
	}{
		{
			name:     "ignored",
			status:   "ignored",
			expected: types.StatusWillNotFix,
		},
		{
			name:     "deferred",
			status:   "deferred",
			expected: types.StatusFixDeferred,
		},
		{
			name:     "needed",
			status:   "needed",
			expected: types.StatusFixDeferred,
		},
		{
			name:     "pending",
			status:   "pending",
			expected: types.StatusFixDeferred,
		},
		{
			name:     "released",
			status:   "released",
			expected: types.StatusFixed,
		},
		{
			name:     "unknown",
			status:   "unknown",
			expected: types.StatusUnknown,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := ubuntu.StatusFromUbuntuStatus(test.status)
			assert.Equal(t, test.expected, actual)
		})
	}
}
