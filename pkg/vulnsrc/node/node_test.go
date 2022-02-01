package node

import (
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/stretchr/testify/assert"
)

func TestVulnSrc_Update(t *testing.T) {
	type want struct {
		key   []string
		value interface{}
	}
	tests := []struct {
		name       string
		dir        string
		wantValues []want
		wantErr    string
	}{
		{
			name: "happy path, npm package only includes CVSS score",
			dir:  filepath.Join("testdata", "happy", "node_cvssnumberonly"),
			wantValues: []want{
				{
					key: []string{"data-source", "npm::Node.js Ecosystem Security Working Group"},
					value: types.DataSource{
						ID:   vulnerability.NodejsSecurityWg,
						Name: "Node.js Ecosystem Security Working Group",
						URL:  "https://github.com/nodejs/security-wg",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2014-7205", "npm::Node.js Ecosystem Security Working Group", "bassmaster"},
					value: types.Advisory{
						PatchedVersions:    []string{">=1.5.2"},
						VulnerableVersions: []string{"<=1.5.1"},
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2014-7205", "nodejs-security-wg"},
					value: types.VulnerabilityDetail{
						ID:          "CVE-2014-7205",
						Title:       "Arbitrary JavaScript Execution",
						Description: "A vulnerability exists in bassmaster <= 1.5.1 that allows for an attacker to provide arbitrary JavaScript that is then executed server side via eval.",
						References:  []string{"https://www.npmjs.org/package/bassmaster", "https://github.com/hapijs/bassmaster/commit/b751602d8cb7194ee62a61e085069679525138c4"},
						CvssScore:   6.5,
					},
				},
				{
					key:   []string{"vulnerability-id", "CVE-2014-7205"},
					value: map[string]interface{}{},
				},
			},
		},
		{
			name: "happy path, npm package includes CVSS score and severity string",
			dir:  filepath.Join("testdata", "happy", "node_cvssnumberandstring"),
			wantValues: []want{
				{
					key: []string{"data-source", "npm::Node.js Ecosystem Security Working Group"},
					value: types.DataSource{
						ID:   vulnerability.NodejsSecurityWg,
						Name: "Node.js Ecosystem Security Working Group",
						URL:  "https://github.com/nodejs/security-wg",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2014-7205", "npm::Node.js Ecosystem Security Working Group", "bassmaster"},
					value: types.Advisory{
						PatchedVersions:    []string{">=1.5.2"},
						VulnerableVersions: []string{"<=1.5.1"},
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2014-7205", "nodejs-security-wg"},
					value: types.VulnerabilityDetail{
						ID:          "CVE-2014-7205",
						Title:       "Arbitrary JavaScript Execution",
						Description: "A vulnerability exists in bassmaster <= 1.5.1 that allows for an attacker to provide arbitrary JavaScript that is then executed server side via eval.",
						References:  []string{"https://www.npmjs.org/package/bassmaster", "https://github.com/hapijs/bassmaster/commit/b751602d8cb7194ee62a61e085069679525138c4"},
						CvssScore:   6.5,
					},
				},
				{
					key:   []string{"vulnerability-id", "CVE-2014-7205"},
					value: map[string]interface{}{},
				},
			},
		},
		{
			name: "happy-(ish) path, core node includes CVSS score and a severity string",
			dir:  filepath.Join("testdata", "happy", "core_cvssnumberandstring"),
			wantValues: []want{
				{
					key: []string{"data-source", "npm::Node.js Ecosystem Security Working Group"},
					value: types.DataSource{
						ID:   vulnerability.NodejsSecurityWg,
						Name: "Node.js Ecosystem Security Working Group",
						URL:  "https://github.com/nodejs/security-wg",
					},
				},
			},
		},
		{
			name: "happy-(ish) path, core node includes no cvss and no severity",
			dir:  filepath.Join("testdata", "happy", "core_nocvssscorepresent"),
			wantValues: []want{
				{
					key: []string{"data-source", "npm::Node.js Ecosystem Security Working Group"},
					value: types.DataSource{
						ID:   vulnerability.NodejsSecurityWg,
						Name: "Node.js Ecosystem Security Working Group",
						URL:  "https://github.com/nodejs/security-wg",
					},
				},
			},
		},
		{
			name: "happy-(ish) path, npm package includes no cvss and no severity",
			dir:  filepath.Join("testdata", "happy", "npm_nocvssseverity"),
			wantValues: []want{
				{
					key: []string{"data-source", "npm::Node.js Ecosystem Security Working Group"},
					value: types.DataSource{
						ID:   vulnerability.NodejsSecurityWg,
						Name: "Node.js Ecosystem Security Working Group",
						URL:  "https://github.com/nodejs/security-wg",
					},
				},
				{
					key:   []string{"advisory-detail", "NSWG-ECO-0", "npm::Node.js Ecosystem Security Working Group", "missingcvss-missingseverity-package"},
					value: types.Advisory{},
				},
				{
					key: []string{"vulnerability-detail", "NSWG-ECO-0", "nodejs-security-wg"},
					value: types.VulnerabilityDetail{
						ID:          "NSWG-ECO-0",
						Description: "The c-ares function ares_parse_naptr_reply(), which is used for parsing NAPTR\nresponses, could be triggered to read memory outside of the given input buffer\nif the passed in DNS response packet was crafted in a particular way.\n\n",
						CvssScore:   -1,
					},
				},
				{
					key:   []string{"vulnerability-id", "NSWG-ECO-0"},
					value: map[string]interface{}{},
				},
			},
		},
		{
			name: "happy-(ish) path, npm package includes null cvss",
			dir:  filepath.Join("testdata", "happy", "npm_nullcvssscore"),
			wantValues: []want{
				{
					key: []string{"data-source", "npm::Node.js Ecosystem Security Working Group"},
					value: types.DataSource{
						ID:   vulnerability.NodejsSecurityWg,
						Name: "Node.js Ecosystem Security Working Group",
						URL:  "https://github.com/nodejs/security-wg",
					},
				},
				{
					key: []string{"advisory-detail", "NSWG-ECO-334", "npm::Node.js Ecosystem Security Working Group", "hubl-server"},
					value: types.Advisory{
						PatchedVersions:    []string{"<0.0.0"},
						VulnerableVersions: []string{"<=99.999.99999"},
					},
				},
				{
					key: []string{"vulnerability-detail", "NSWG-ECO-334", "nodejs-security-wg"},
					value: types.VulnerabilityDetail{
						ID:          "NSWG-ECO-334",
						Title:       "Downloads resources over HTTP",
						Description: "The hubl-server module is a wrapper for the HubL Development Server.\n\nDuring installation hubl-server downloads a set of dependencies from api.hubapi.com. It appears in the code that these files are downloaded over HTTPS however the api.hubapi.com endpoint redirects to a HTTP url. Because of this behavior an attacker with the ability to man-in-the-middle a developer or system performing a package installation could compromise the integrity of the installation.",
						CvssScore:   -1,
					},
				},
				{
					key:   []string{"vulnerability-id", "NSWG-ECO-334"},
					value: map[string]interface{}{},
				},
			},
		},
		{
			name:    "sad path, invalid json",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "invalid character",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()

			err := db.Init(tempDir)
			require.NoError(t, err)
			defer db.Close()

			vs := NewVulnSrc()
			err = vs.Update(tt.dir)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.NoError(t, db.Close()) // Need to close before dbtest.JSONEq is called
			for _, w := range tt.wantValues {
				dbtest.JSONEq(t, db.Path(tempDir), w.key, w.value, w.key)
			}
		})
	}
}
