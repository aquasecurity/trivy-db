package nvd

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/utils"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestVulnSrc_Update(t *testing.T) {
	testCases := []struct {
		name    string
		dir     string
		cveID   string
		want    types.VulnerabilityDetail
		wantErr string
	}{
		{
			name:  "happy path",
			dir:   filepath.Join("testdata", "happy"),
			cveID: "CVE-2020-0001",
			want: types.VulnerabilityDetail{
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
		{
			name:  "happy path (**REJECT** in description)",
			dir:   filepath.Join("testdata", "reject in description"),
			cveID: "CVE-2020-0001",
			want: types.VulnerabilityDetail{
				Description:      "** REJECT ** test description",
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
		{
			name:    "sad path (dir doesn't exist)",
			dir:     filepath.Join("testdata", "badpathdoesnotexist"),
			wantErr: "no such file or directory",
		},
		{
			name:    "sad path (failed to decode)",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "failed to decode NVD JSON",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cacheDir, err := ioutil.TempDir("", "nvd")
			require.NoError(t, err)
			err = db.Init(cacheDir)
			require.NoError(t, err)
			defer db.Close()
			defer os.RemoveAll(cacheDir)

			vs := NewVulnSrc()
			err = vs.Update(tc.dir)

			switch {
			case tc.wantErr != "":
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tc.wantErr, tc.name)
			default:
				assert.NoError(t, err, tc.name)
				dbc := db.Config{}
				got, err := dbc.GetVulnerabilityDetail(tc.cveID)
				require.NoError(t, err)
				assert.Equal(t, tc.want, got["nvd"])
			}
		})
	}
}
