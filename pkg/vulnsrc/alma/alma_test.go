package alma_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/alma"
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
			name: "happy path",
			dir:  filepath.Join("testdata", "happy"),
			wantValues: []want{
				{
					key: []string{"advisory-detail", "CVE-2021-27918", "alma 8", "go-toolset:rhel8::go-toolset"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-27918", "alma 8", "go-toolset:rhel8::golang"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-31525", "alma 8", "go-toolset:rhel8::go-toolset"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-31525", "alma 8", "go-toolset:rhel8::golang"},
					value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2021-27918", "alma"},
					value: types.VulnerabilityDetail{
						Severity:    types.SeverityMedium,
						Title:       "Moderate: go-toolset:rhel8 security, bug fix, and enhancement update",
						Description: "Go Toolset provides the Go programming language tools and libraries. Go is alternatively known as golang. \n\nThe following packages have been upgraded to a later upstream version: golang (1.15.14). (BZ#1982287)\n\nSecurity Fix(es):\n\n* golang: encoding/xml: infinite loop when using xml.NewTokenDecoder with a custom TokenReader (CVE-2021-27918)\n\n* golang: net/http: panic in ReadRequest and ReadResponse when reading a very large header (CVE-2021-31525)\n\n* golang: archive/zip: malformed archive may cause panic or memory exhaustion (CVE-2021-33196)\n\n* golang: crypto/tls: certificate of wrong type is causing TLS client to panic (CVE-2021-34558)\n\nFor more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.\n\nBug Fix(es):\n\n* FIPS mode AES CBC CryptBlocks incorrectly re-initializes IV in file crypto/internal/boring/aes.go (BZ#1978567)\n\n* FIPS mode AES CBC Decrypter produces incorrect result (BZ#1983976)",
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2021-31525", "alma"},
					value: types.VulnerabilityDetail{
						Severity:    types.SeverityMedium,
						Title:       "Moderate: go-toolset:rhel8 security, bug fix, and enhancement update",
						Description: "Go Toolset provides the Go programming language tools and libraries. Go is alternatively known as golang. \n\nThe following packages have been upgraded to a later upstream version: golang (1.15.14). (BZ#1982287)\n\nSecurity Fix(es):\n\n* golang: encoding/xml: infinite loop when using xml.NewTokenDecoder with a custom TokenReader (CVE-2021-27918)\n\n* golang: net/http: panic in ReadRequest and ReadResponse when reading a very large header (CVE-2021-31525)\n\n* golang: archive/zip: malformed archive may cause panic or memory exhaustion (CVE-2021-33196)\n\n* golang: crypto/tls: certificate of wrong type is causing TLS client to panic (CVE-2021-34558)\n\nFor more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.\n\nBug Fix(es):\n\n* FIPS mode AES CBC CryptBlocks incorrectly re-initializes IV in file crypto/internal/boring/aes.go (BZ#1978567)\n\n* FIPS mode AES CBC Decrypter produces incorrect result (BZ#1983976)",
					},
				},
				{
					key:   []string{"vulnerability-id", "CVE-2021-27918"},
					value: map[string]interface{}{},
				},
				{
					key:   []string{"vulnerability-id", "CVE-2021-31525"},
					value: map[string]interface{}{},
				},
			},
		},
		{
			name:    "sad path",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "failed to decode Alma erratum",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()

			err := db.Init(tempDir)
			require.NoError(t, err)
			defer db.Close()

			vs := alma.NewVulnSrc()
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
