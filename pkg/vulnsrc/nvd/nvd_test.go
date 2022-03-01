package nvd

import (
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/utils"

	"github.com/aquasecurity/trivy-db/pkg/types"
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
					Key: []string{"vulnerability-detail", "CVE-2020-0001", nvdDir},
					Value: types.VulnerabilityDetail{
						Description:      "In getProcessRecordLocked of ActivityManagerService.java isolated apps are not handled correctly. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Product: Android Versions: Android-8.0, Android-8.1, Android-9, and Android-10 Android ID: A-140055304",
						CvssScore:        7.2,
						CvssVector:       "AV:L/AC:L/Au:N/C:C/I:C/A:C",
						CvssScoreV3:      7.8,
						CvssVectorV3:     "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
						Severity:         types.SeverityHigh,
						SeverityV3:       types.SeverityHigh,
						CweIDs:           []string{"CWE-269"},
						References:       []string{"https://source.android.com/security/bulletin/2020-01-01"},
						LastModifiedDate: utils.MustTimeParse("2020-01-01T01:01:00Z"),
						PublishedDate:    utils.MustTimeParse("2001-01-01T01:01:00Z"),
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
