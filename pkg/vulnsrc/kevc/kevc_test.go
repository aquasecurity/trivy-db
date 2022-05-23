package kevc_test

import (
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/kevc"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
	"path/filepath"
	"testing"
)

func TestVulnSrc_Update(t *testing.T) {
	tests := []struct {
		name       string
		dir        string
		wantValues []vulnsrctest.WantValues
		wantErr    string
	}{
		{
			name: "happy path",
			dir:  filepath.Join("testdata", "happy"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"data-source", "Known Exploited Vulnerability Catalog"},
					Value: types.DataSource{
						ID:   vulnerability.KnownExploitedVulnerabilityCatalog,
						Name: "Known Exploited Vulnerability Catalog",
						URL:  "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
					},
				},
				{
					Key: []string{"vulnerability-exploitable", "CVE-2022-0609", "known-exploited-vulnerability-catalog"},
					Value: types.VulnerabilityExploitable{
						DataSource: &types.DataSource{
							ID:   vulnerability.KnownExploitedVulnerabilityCatalog,
							Name: "Known Exploited Vulnerability Catalog",
							URL:  "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
						},
						Description:    "The vulnerability exists due to a use-after-free error within the Animation component in Google Chrome.",
						RequiredAction: "Apply updates per vendor instructions.",
						DateAdded:      utils.MustTimeParse("2022-02-15T00:00:00Z"),
						DueDate:        utils.MustTimeParse("2022-03-01T00:00:00Z"),
					},
				},
			},
		},
		{
			name:    "sad path",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "failed to decode json",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := kevc.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
			})
		})
	}
}
