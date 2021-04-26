package govulndb

import (
	"io/ioutil"
	"os"
	"testing"

	bolt "go.etcd.io/bbolt"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
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
			dir:   "./testdata",
			cveID: "GO-2021-0097",
			want: types.VulnerabilityDetail{
				ID:          "GO-2021-0097",
				Title:       "vulnerability in package github.com/dhowden/tag",
				Description: "Due to improper bounds checking a number of methods can trigger a panic due to attempted\nout-of-bounds reads. If the package is used to parse user supplied input this may be\nused as a vector for a denial of service attack.\n",
				References: []string{"https://github.com/dhowden/tag/commit/d52dcb253c63a153632bfee5f269dd411dcd8e96",
					"https://github.com/dhowden/tag/commit/a92213460e4838490ce3066ef11dc823cdc1740e",
					"https://github.com/dhowden/tag/commit/4b595ed4fac79f467594aa92f8953f90f817116e",
					"https://github.com/dhowden/tag/commit/6b18201aa5c5535511802ddfb4e4117686b4866d",
					"https://go.googlesource.com/vulndb/+/refs/heads/main/reports/GO-2021-0097.toml",
				},
				LastModifiedDate: utils.MustTimeParse("2021-04-14T12:00:00Z"),
				PublishedDate:    utils.MustTimeParse("2021-04-14T12:00:00Z"),
			},
		},
		{
			name:    "sad path",
			dir:     "./sad",
			wantErr: "no such file or directory",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cacheDir, err := ioutil.TempDir("", "go")
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
				assert.Equal(t, tc.want, got["go::vulndb"])
			}
		})
	}
}

func TestVulnSrc_Commit(t *testing.T) {
	testCases := []struct {
		name                   string
		cves                   []Entry
		putAdvisoryDetail      []db.OperationPutAdvisoryDetailExpectation
		putVulnerabilityDetail []db.OperationPutVulnerabilityDetailExpectation
		putSeverity            []db.OperationPutSeverityExpectation
		expectedErrorMsg       string
	}{
		{
			name: "happy path",
			cves: []Entry{
				{
					ID:        "GO-2021-0097",
					Published: *utils.MustTimeParse("2021-04-14T12:00:00Z"),
					Modified:  *utils.MustTimeParse("2021-04-14T12:00:00Z"),
					Withdrawn: nil,
					Aliases:   []string{"CVE-2020-29242"},
					Package: Package{
						Ecosystem: "go",
						Name:      "github.com/dhowden/tag",
					},
					Details: "Due to improper bounds checking a number of methods can trigger a panic due to attempted\nout-of-bounds reads. If the package is used to parse user supplied input this may be\nused as a vector for a denial of service attack.\n",
					Affects: Affects{
						Ranges: []AffectsRange{
							{
								Type:       2,
								Introduced: "",
								Fixed:      "v0.0.0-20201120070457-d52dcb253c63",
							},
						},
					},
					References: []Reference{
						{
							Type: "fix",
							URL:  "https://github.com/dhowden/tag/commit/d52dcb253c63a153632bfee5f269dd411dcd8e96",
						},
						{
							Type: "misc",
							URL:  "https://github.com/dhowden/tag/commit/a92213460e4838490ce3066ef11dc823cdc1740e",
						},
						{
							Type: "misc",
							URL:  "https://github.com/dhowden/tag/commit/4b595ed4fac79f467594aa92f8953f90f817116e",
						},
						{
							Type: "misc",
							URL:  "https://github.com/dhowden/tag/commit/6b18201aa5c5535511802ddfb4e4117686b4866d",
						},
					},
					Extra: struct{ Go GoSpecific }{
						Go: GoSpecific{
							GOOS:    nil,
							GOARCH:  nil,
							Symbols: []string{"readPICFrame", "readAPICFrame", "readTextWithDescrFrame", "readAtomData"},
							URL:     "https://go.googlesource.com/vulndb/+/refs/heads/main/reports/GO-2021-0097.toml",
						},
					},
				},
			},
			putVulnerabilityDetail: []db.OperationPutVulnerabilityDetailExpectation{
				{
					Args: db.OperationPutVulnerabilityDetailArgs{
						TxAnything:      true,
						VulnerabilityID: "GO-2021-0097",
						Source:          vulnerability.GoVulnDB,
						Vulnerability: types.VulnerabilityDetail{
							ID:          "GO-2021-0097",
							Title:       "vulnerability in package github.com/dhowden/tag",
							Description: "Due to improper bounds checking a number of methods can trigger a panic due to attempted\nout-of-bounds reads. If the package is used to parse user supplied input this may be\nused as a vector for a denial of service attack.\n",
							References: []string{"https://github.com/dhowden/tag/commit/d52dcb253c63a153632bfee5f269dd411dcd8e96",
								"https://github.com/dhowden/tag/commit/a92213460e4838490ce3066ef11dc823cdc1740e",
								"https://github.com/dhowden/tag/commit/4b595ed4fac79f467594aa92f8953f90f817116e",
								"https://github.com/dhowden/tag/commit/6b18201aa5c5535511802ddfb4e4117686b4866d",
								"https://go.googlesource.com/vulndb/+/refs/heads/main/reports/GO-2021-0097.toml",
							},
							LastModifiedDate: utils.MustTimeParse("2021-04-14T12:00:00Z"),
							PublishedDate:    utils.MustTimeParse("2021-04-14T12:00:00Z"),
						},
					},
				},
			},
			putAdvisoryDetail: []db.OperationPutAdvisoryDetailExpectation{
				{
					Args: db.OperationPutAdvisoryDetailArgs{
						TxAnything:      true,
						Source:          "go::vulndb",
						PkgName:         "github.com/dhowden/tag",
						VulnerabilityID: "GO-2021-0097",
						Advisory: types.Advisory{
							PatchedVersions: []string{"v0.0.0-20201120070457-d52dcb253c63"},
						},
					},
				},
			},
			putSeverity: []db.OperationPutSeverityExpectation{
				{
					Args: db.OperationPutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "GO-2021-0097",
						Severity:        types.SeverityUnknown,
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tx := &bolt.Tx{}
			mockDBConfig := new(db.MockOperation)
			mockDBConfig.ApplyPutAdvisoryDetailExpectations(tc.putAdvisoryDetail)
			mockDBConfig.ApplyPutVulnerabilityDetailExpectations(tc.putVulnerabilityDetail)
			mockDBConfig.ApplyPutSeverityExpectations(tc.putSeverity)

			ac := VulnSrc{dbc: mockDBConfig}
			err := ac.commit(tx, tc.cves)

			switch {
			case tc.expectedErrorMsg != "":
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrorMsg, tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}
			mockDBConfig.AssertExpectations(t)
		})
	}
}
