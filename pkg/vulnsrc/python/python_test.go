package python

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVulnSrc_Update(t *testing.T) {
	type args struct {
		dir string
	}
	testCases := []struct {
		name             string
		args             args
		expectedAdvisory []Advisory
		expectErr        bool
		expectPackage    string
	}{
		{
			name: "happy path",
			args: args{
				dir: "testdata/full",
			},
			expectedAdvisory: []Advisory{
				{
					VulnerabilityID: "CVE-2018-9986",
					Specs:           []string{"<1.7.2"},
				},
				{
					VulnerabilityID: "CVE-2018-9987",
					Specs:           []string{"<1.7.2"},
				},
				{
					VulnerabilityID: "CVE-2018-9990",
					Specs:           []string{"<1.7.2"},
				},
				{
					VulnerabilityID: "CVE-2018-9999",
					Specs:           []string{"<1.7.2"},
				},
				{
					VulnerabilityID: "CVE-2019-18933",
					Specs:           []string{"<2.0.7"},
				},
				{
					VulnerabilityID: "CVE-2020-10935",
					Specs:           []string{"<2.1.3"},
				},
				{
					VulnerabilityID: "CVE-2020-9444",
					Specs:           []string{"<2.1.3"},
				},
			},
			expectErr:     false,
			expectPackage: "zulip",
		},
		{
			name: "happy path uppercase kuber",
			args: args{
				dir: "testdata/uppercase",
			},
			expectedAdvisory: []Advisory{
				{
					VulnerabilityID: "CVE-2019-11324",
					Specs:           []string{"<10.0.1"},
				},
			},
			expectErr:     false,
			expectPackage: "kuber",
		},
		{
			name: "happy path hyphen kuber",
			args: args{
				dir: "testdata/hyphen",
			},
			expectedAdvisory: []Advisory{
				{
					VulnerabilityID: "CVE-2019-11324",
					Specs:           []string{"<10.0.1"},
				},
			},
			expectErr:     false,
			expectPackage: "ku-ber",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := db.Init("testdata")
			defer os.RemoveAll("testdata/db")
			require.NoError(t, err)
			vulSec := NewVulnSrc()
			err = vulSec.Update(tc.args.dir)
			require.NoError(t, err, tc.name)
			var advisories []Advisory
			for _, a := range tc.expectedAdvisory {
				adv, err := db.Config{}.GetAdvisoryDetails(a.VulnerabilityID)
				require.NoError(t, err)
				for _, advis := range adv {
					require.Equal(t, tc.expectPackage, advis.PackageName)
					rawAdv, err := json.Marshal(advis.AdvisoryItem)
					require.NoError(t, err)
					var pythonAdv Advisory
					err = json.Unmarshal(rawAdv, &pythonAdv)
					require.NoError(t, err)
					pythonAdv.VulnerabilityID = a.VulnerabilityID
					advisories = append(advisories, pythonAdv)
				}
			}
			sort.Slice(advisories[:], func(i, j int) bool {
				return strings.Compare(advisories[i].VulnerabilityID, advisories[j].VulnerabilityID) <= 0
			})
			require.Equal(t, tc.expectedAdvisory, advisories, "expected %v for package zulip, got: %v", tc.expectedAdvisory, advisories)
		})
	}
}
func TestVulnSrc_Get(t *testing.T) {
	type args struct {
		release string
		pkgName string
	}

	tests := []struct {
		name                       string
		args                       args
		forEachAdvisoryExpectation db.OperationForEachAdvisoryExpectation
		want                       []Advisory
		wantErr                    string
	}{
		{
			name: "happy path",
			args: args{
				release: "python-safety-db",
				pkgName: "django",
			},
			forEachAdvisoryExpectation: db.OperationForEachAdvisoryExpectation{
				Args: db.OperationForEachAdvisoryArgs{
					Source:  "python-safety-db",
					PkgName: "django",
				},
				Returns: db.OperationForEachAdvisoryReturns{
					Value: map[string][]byte{
						"GHSA-5hg3-6c2f-f3wr": []byte(`{"specs": ["<2.8.0"]}`),
					},
				},
			},
			want: []Advisory{
				{
					VulnerabilityID: "GHSA-5hg3-6c2f-f3wr",
					Specs:           []string{"<2.8.0"},
				},
			},
		},
		{
			name: "happy path uppercase",
			args: args{
				release: "python-safety-db",
				pkgName: "Django",
			},
			forEachAdvisoryExpectation: db.OperationForEachAdvisoryExpectation{
				Args: db.OperationForEachAdvisoryArgs{
					Source:  "python-safety-db",
					PkgName: "django",
				},
				Returns: db.OperationForEachAdvisoryReturns{
					Value: map[string][]byte{
						"GHSA-5hg3-6c2f-f3wr": []byte(`{"specs": ["<2.8.0"]}`),
					},
				},
			},
			want: []Advisory{
				{
					VulnerabilityID: "GHSA-5hg3-6c2f-f3wr",
					Specs:           []string{"<2.8.0"},
				},
			},
		},
		{
			name: "happy path hyphen",
			args: args{
				release: "python-safety-db",
				pkgName: "py_gfm",
			},
			forEachAdvisoryExpectation: db.OperationForEachAdvisoryExpectation{
				Args: db.OperationForEachAdvisoryArgs{
					Source:  "python-safety-db",
					PkgName: "py-gfm",
				},
				Returns: db.OperationForEachAdvisoryReturns{
					Value: map[string][]byte{
						"GHSA-5hg3-6c2f-f3wr": []byte(`{"specs": ["<2.8.0"]}`),
					},
				},
			},
			want: []Advisory{
				{
					VulnerabilityID: "GHSA-5hg3-6c2f-f3wr",
					Specs:           []string{"<2.8.0"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDBConfig := new(db.MockOperation)
			mockDBConfig.ApplyForEachAdvisoryExpectation(tt.forEachAdvisoryExpectation)

			vs := VulnSrc{
				dbc: mockDBConfig,
			}
			got, err := vs.Get(tt.args.pkgName)
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
			} else {
				assert.NoError(t, err, tt.name)
			}
			assert.Equal(t, tt.want, got, tt.name)
		})
	}
}

func TestAdvisoryDB_UnmarshalJSON(t *testing.T) {
	b, err := ioutil.ReadFile("testdata/full/python-safety-db/data/insecure_full.json")
	require.NoError(t, err)
	advisories := AdvisoryDB{}
	err = json.Unmarshal(b, &advisories)
	require.NoError(t, err)
	expectedAdvisory := AdvisoryDB{
		"zulip": []RawAdvisory{
			{
				ID:       "pyup.io-38116",
				Advisory: "Zulip 2.0.7 inlcudes a fix for insecure account creation via social authentication - see CVE-2019-18933. It also adds backend enforcement of zxcvbn password strength checks.",
				Cve:      "CVE-2019-18933",
				Specs:    []string{"<2.0.7"},
				Version:  "<2.0.7",
			},
			{
				ID:       "pyup.io-38200",
				Advisory: "Zulip 2.1.3 includes fixes for:\r\n- CVE-2020-9444: Prevent reverse tabnapping attacks.                                                 \r\n- CVE-2020-9445: Remove unused and insecure modal_link feature.                                      \r\n- CVE-2020-10935: Fix XSS vulnerability in local link rewriting.",
				Cve:      "CVE-2020-9444,CVE-2020-10935",
				Specs:    []string{"<2.1.3"},
				Version:  "<2.1.3",
			},
			{
				ID:       "pyup.io-36168",
				Advisory: "Zulip 1.7.2 is a security release, with a handful of cherry-picked changes since 1.7.1.\r\n- CVE-2018-9986: Fix XSS issues with frontend markdown processor.\r\n- CVE-2018-9987: Fix XSS issue with muting notifications.\r\n- CVE-2018-9990: Fix XSS issue with stream names in topic typeahead.\r\n- CVE-2018-9999: Fix XSS issue with user uploads.  The fix for this adds a Content-Security-Policy for the `LOCAL_UPLOADS_DIR` storage backend for user-uploaded files.",
				Cve:      "CVE-2018-9986,CVE-2018-9987,CVE-2018-9990,CVE-2018-9999",
				Specs:    []string{"<1.7.2"},
				Version:  "<1.7.2",
			},
		},
		"kuber": []RawAdvisory{
			{
				ID:       "pyup.io-38099",
				Advisory: "Kuber 10.0.1 bumps the urllib3 version to pick up security fix for CVE-2019-11324.",
				Cve:      "CVE-2019-11324",
				Specs:    []string{"<10.0.1"},
				Version:  "<10.0.1",
			},
			{
				ID:       "pyup.io-36979",
				Advisory: "kuber 9.0.0a1 bumps urllib3 version to pick up security fix for CVE-2018-20060.",
				Cve:      "",
				Specs:    []string{"<9.0.0a1"},
				Version:  "<9.0.0a1",
			},
		},
	}
	assert.Equal(t, expectedAdvisory, advisories)
}
