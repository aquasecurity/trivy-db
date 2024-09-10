package ubuntu_test

import (
	"testing"

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
