package nvd

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
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
					Key: []string{"vulnerability-detail", "CVE-2020-0001", "nvd"},
					Value: types.VulnerabilityDetail{
						Description:      "In getProcessRecordLocked of ActivityManagerService.java isolated apps are not handled correctly. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Product: Android Versions: Android-8.0, Android-8.1, Android-9, and Android-10 Android ID: A-140055304",
						CvssScore:        7.2,
						CvssVector:       "AV:L/AC:L/Au:N/C:C/I:C/A:C",
						CvssScoreV3:      7.8,
						CvssVectorV3:     "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
						Severity:         types.SeverityHigh,
						SeverityV3:       types.SeverityHigh,
						References:       []string{"https://source.android.com/security/bulletin/2020-01-01"},
						LastModifiedDate: utils.MustTimeParse("2021-07-21T11:39:23.747Z"),
						PublishedDate:    utils.MustTimeParse("2020-01-08T19:15:12.843Z"),
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2023-0001", "nvd"},
					Value: types.VulnerabilityDetail{
						Description:      "An information exposure vulnerability in the Palo Alto Networks Cortex XDR agent on Windows devices allows a local system administrator to disclose the admin password for the agent in cleartext, which bad actors can then use to execute privileged cytool commands that disable or uninstall the agent.",
						CvssScoreV3:      6.7,
						CvssVectorV3:     "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
						SeverityV3:       types.SeverityMedium,
						CweIDs:           []string{"CWE-319"},
						References:       []string{"https://security.paloaltonetworks.com/CVE-2023-0001"},
						LastModifiedDate: utils.MustTimeParse("2023-11-21T19:15:08.073Z"),
						PublishedDate:    utils.MustTimeParse("2023-02-08T18:15:11.523Z"),
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2024-0069", "nvd"},
					Value: types.VulnerabilityDetail{
						Description:      "Rejected reason: This CVE ID was unused by the CNA.",
						LastModifiedDate: utils.MustTimeParse("2023-11-28T00:15:07.140Z"),
						PublishedDate:    utils.MustTimeParse("2023-11-28T00:15:07.140Z"),
					},
				},
			},
		},
		{
			name:    "sad path (dir doesn't exist)",
			dir:     filepath.Join("testdata", "badPath"),
			wantErr: "no such file or directory",
		},
		{
			name:    "sad path (failed to decode)",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "failed to decode NVD JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
			})
		})
	}
}
