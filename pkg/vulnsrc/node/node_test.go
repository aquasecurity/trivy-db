package node

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/stretchr/testify/assert"
	bolt "go.etcd.io/bbolt"
)

func TestVulnSrc_Commit(t *testing.T) {
	testCases := []struct {
		name                   string
		inputFile              string
		putAdvisory            []db.PutAdvisoryExpectation
		putVulnerabilityDetail []db.PutVulnerabilityDetailExpectation
		putSeverity            []db.PutSeverityExpectation
		expectedErrorMsg       string
	}{
		{
			name:      "happy path, npm package only includes CVSS score",
			inputFile: "npm_cvssnumberonly.json",
			putAdvisory: []db.PutAdvisoryExpectation{
				{
					Args: db.PutAdvisoryArgs{
						TxAnything:      true,
						Source:          "nodejs-security-wg",
						PkgName:         "bassmaster",
						VulnerabilityID: "CVE-2014-7205",
						Advisory: Advisory{
							VulnerableVersions: "<=1.5.1",
							PatchedVersions:    ">=1.5.2",
						},
					},
				},
			},
			putVulnerabilityDetail: []db.PutVulnerabilityDetailExpectation{
				{
					Args: db.PutVulnerabilityDetailArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2014-7205",
						Source:          vulnerability.NodejsSecurityWg,
						Vulnerability: types.VulnerabilityDetail{
							ID:          "CVE-2014-7205",
							CvssScore:   6.5,
							References:  []string{"https://www.npmjs.org/package/bassmaster", "https://github.com/hapijs/bassmaster/commit/b751602d8cb7194ee62a61e085069679525138c4"},
							Title:       "Arbitrary JavaScript Execution",
							Description: "A vulnerability exists in bassmaster <= 1.5.1 that allows for an attacker to provide arbitrary JavaScript that is then executed server side via eval.",
						},
					},
				},
			},
			putSeverity: []db.PutSeverityExpectation{
				{
					Args: db.PutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2014-7205",
						Severity:        types.SeverityUnknown,
					},
				},
			},
		},
		{
			name:      "happy path, npm package includes CVSS score and severity string",
			inputFile: "npm_cvssnumberandstring.json",
			putAdvisory: []db.PutAdvisoryExpectation{
				{
					Args: db.PutAdvisoryArgs{
						TxAnything:      true,
						Source:          "nodejs-security-wg",
						PkgName:         "bassmaster",
						VulnerabilityID: "CVE-2014-7205",
						Advisory: Advisory{
							VulnerableVersions: "<=1.5.1",
							PatchedVersions:    ">=1.5.2",
						},
					},
				},
			},
			putVulnerabilityDetail: []db.PutVulnerabilityDetailExpectation{
				{
					Args: db.PutVulnerabilityDetailArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2014-7205",
						Source:          vulnerability.NodejsSecurityWg,
						Vulnerability: types.VulnerabilityDetail{
							ID:          "CVE-2014-7205",
							CvssScore:   6.5,
							References:  []string{"https://www.npmjs.org/package/bassmaster", "https://github.com/hapijs/bassmaster/commit/b751602d8cb7194ee62a61e085069679525138c4"},
							Title:       "Arbitrary JavaScript Execution",
							Description: "A vulnerability exists in bassmaster <= 1.5.1 that allows for an attacker to provide arbitrary JavaScript that is then executed server side via eval.",
						},
					},
				},
			},
			putSeverity: []db.PutSeverityExpectation{
				{
					Args: db.PutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "CVE-2014-7205",
						Severity:        types.SeverityUnknown,
					},
				},
			},
		},
		{
			name:      "happy-(ish) path, core node includes CVSS score and a severity string",
			inputFile: "core_cvssnumberandstring.json",
		},
		{
			name:      "happy-(ish) path, core node includes no cvss and no severity",
			inputFile: "core_nocvssscorepresent.json",
		},
		{
			name:      "happy-(ish) path, npm package includes no cvss and no severity",
			inputFile: "npm_nocvssseverity.json",
			putAdvisory: []db.PutAdvisoryExpectation{
				{
					Args: db.PutAdvisoryArgs{
						TxAnything:      true,
						Source:          "nodejs-security-wg",
						PkgName:         "missingcvss-missingseverity-package",
						VulnerabilityID: "NSWG-ECO-0",
						Advisory:        Advisory{},
					},
				},
			},
			putVulnerabilityDetail: []db.PutVulnerabilityDetailExpectation{
				{
					Args: db.PutVulnerabilityDetailArgs{
						TxAnything:      true,
						VulnerabilityID: "NSWG-ECO-0",
						Source:          vulnerability.NodejsSecurityWg,
						Vulnerability: types.VulnerabilityDetail{
							ID:          "NSWG-ECO-0",
							CvssScore:   -1,
							Description: "The c-ares function ares_parse_naptr_reply(), which is used for parsing NAPTR\nresponses, could be triggered to read memory outside of the given input buffer\nif the passed in DNS response packet was crafted in a particular way.\n\n",
						},
					},
				},
			},
			putSeverity: []db.PutSeverityExpectation{
				{
					Args: db.PutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "NSWG-ECO-0",
						Severity:        types.SeverityUnknown,
					},
				},
			},
		},
		{
			name:      "happy-(ish) path, npm package includes null cvss",
			inputFile: "npm_nullcvssscore.json",
			putAdvisory: []db.PutAdvisoryExpectation{
				{
					Args: db.PutAdvisoryArgs{
						TxAnything:      true,
						Source:          "nodejs-security-wg",
						PkgName:         "hubl-server",
						VulnerabilityID: "NSWG-ECO-334",
						Advisory: Advisory{
							VulnerableVersions: "<=99.999.99999",
							PatchedVersions:    "<0.0.0",
						},
					},
				},
			},
			putVulnerabilityDetail: []db.PutVulnerabilityDetailExpectation{
				{
					Args: db.PutVulnerabilityDetailArgs{
						TxAnything:      true,
						VulnerabilityID: "NSWG-ECO-334",
						Source:          vulnerability.NodejsSecurityWg,
						Vulnerability: types.VulnerabilityDetail{
							ID:          "NSWG-ECO-334",
							CvssScore:   -1,
							Description: "The hubl-server module is a wrapper for the HubL Development Server.\n\nDuring installation hubl-server downloads a set of dependencies from api.hubapi.com. It appears in the code that these files are downloaded over HTTPS however the api.hubapi.com endpoint redirects to a HTTP url. Because of this behavior an attacker with the ability to man-in-the-middle a developer or system performing a package installation could compromise the integrity of the installation.",
							Title:       "Downloads resources over HTTP",
						},
					},
				},
			},
			putSeverity: []db.PutSeverityExpectation{
				{
					Args: db.PutSeverityArgs{
						TxAnything:      true,
						VulnerabilityID: "NSWG-ECO-334",
						Severity:        types.SeverityUnknown,
					},
				},
			},
		},
		{
			name:             "sad path, invalid json",
			inputFile:        "invalidvuln.json",
			expectedErrorMsg: "invalid character",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tx := &bolt.Tx{}
			mockDBConfig := new(db.MockOperation)
			mockDBConfig.ApplyPutAdvisoryExpectations(tc.putAdvisory)
			mockDBConfig.ApplyPutVulnerabilityDetailExpectations(tc.putVulnerabilityDetail)
			mockDBConfig.ApplyPutSeverityExpectations(tc.putSeverity)

			ac := VulnSrc{dbc: mockDBConfig}

			filePath := fmt.Sprintf("testdata/%s", tc.inputFile)
			f, err := os.Open(filePath)
			require.NoError(t, err, tc.name)
			err = ac.commit(tx, f)

			switch {
			case tc.expectedErrorMsg != "":
				assert.Contains(t, err.Error(), tc.expectedErrorMsg, tc.name)
			default:
				assert.NoError(t, err, tc.name)
			}
			mockDBConfig.AssertExpectations(t)
		})
	}
}
