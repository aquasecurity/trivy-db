package alma_test

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/alma"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
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
					Key: []string{"data-source", "alma 8"},
					Value: types.DataSource{
						ID:   vulnerability.Alma,
						Name: "AlmaLinux Product Errata",
						URL:  "https://errata.almalinux.org/",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-27918", "alma 8", "go-toolset:rhel8::go-toolset"},
					Value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-27918", "alma 8", "go-toolset:rhel8::golang"},
					Value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-31525", "alma 8", "go-toolset:rhel8::go-toolset"},
					Value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-31525", "alma 8", "go-toolset:rhel8::golang"},
					Value: types.Advisory{
						FixedVersion: "1.15.14-1.module_el8.4.0+2519+614b07b8",
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2021-27918", "alma"},
					Value: types.VulnerabilityDetail{
						Severity:    types.SeverityMedium,
						Title:       "Moderate: go-toolset:rhel8 security, bug fix, and enhancement update",
						Description: "Go Toolset provides the Go programming language tools and libraries. Go is alternatively known as golang. \n\nThe following packages have been upgraded to a later upstream version: golang (1.15.14). (BZ#1982287)\n\nSecurity Fix(es):\n\n* golang: encoding/xml: infinite loop when using xml.NewTokenDecoder with a custom TokenReader (CVE-2021-27918)\n\n* golang: net/http: panic in ReadRequest and ReadResponse when reading a very large header (CVE-2021-31525)\n\n* golang: archive/zip: malformed archive may cause panic or memory exhaustion (CVE-2021-33196)\n\n* golang: crypto/tls: certificate of wrong type is causing TLS client to panic (CVE-2021-34558)\n\nFor more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.\n\nBug Fix(es):\n\n* FIPS mode AES CBC CryptBlocks incorrectly re-initializes IV in file crypto/internal/boring/aes.go (BZ#1978567)\n\n* FIPS mode AES CBC Decrypter produces incorrect result (BZ#1983976)",
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2021-31525", "alma"},
					Value: types.VulnerabilityDetail{
						Severity:    types.SeverityMedium,
						Title:       "Moderate: go-toolset:rhel8 security, bug fix, and enhancement update",
						Description: "Go Toolset provides the Go programming language tools and libraries. Go is alternatively known as golang. \n\nThe following packages have been upgraded to a later upstream version: golang (1.15.14). (BZ#1982287)\n\nSecurity Fix(es):\n\n* golang: encoding/xml: infinite loop when using xml.NewTokenDecoder with a custom TokenReader (CVE-2021-27918)\n\n* golang: net/http: panic in ReadRequest and ReadResponse when reading a very large header (CVE-2021-31525)\n\n* golang: archive/zip: malformed archive may cause panic or memory exhaustion (CVE-2021-33196)\n\n* golang: crypto/tls: certificate of wrong type is causing TLS client to panic (CVE-2021-34558)\n\nFor more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.\n\nBug Fix(es):\n\n* FIPS mode AES CBC CryptBlocks incorrectly re-initializes IV in file crypto/internal/boring/aes.go (BZ#1978567)\n\n* FIPS mode AES CBC Decrypter produces incorrect result (BZ#1983976)",
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2021-27918"},
					Value: map[string]interface{}{},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2021-31525"},
					Value: map[string]interface{}{},
				},
			},
		},
		{
			name: "duplicate advisories",
			dir:  filepath.Join("testdata", "duplicate"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"advisory-detail", "CVE-2020-7754", "alma 8", "nodejs:14::nodejs-nodemon"},
					Value: types.Advisory{
						FixedVersion: "2.0.3-1.module_el8.3.0+2022+0cf59502",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2020-7754", "alma 8", "nodejs:14::nodejs-packaging"},
					Value: types.Advisory{
						FixedVersion: "23-3.module_el8.3.0+2022+0cf59502",
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2020-7754", "alma"},
					Value: types.VulnerabilityDetail{
						Severity:    types.SeverityHigh,
						Title:       "Important: nodejs:14 security and bug fix update",
						Description: "Node.js is a software development platform for building fast and scalable network applications in the JavaScript programming language. \n\nThe following packages have been upgraded to a later upstream version: nodejs (14.15.4).\n\nSecurity Fix(es):\n\n* nodejs-npm-user-validate: improper input validation when validating user emails leads to ReDoS (CVE-2020-7754)\n\n* nodejs-y18n: prototype pollution vulnerability (CVE-2020-7774)\n\n* nodejs-ini: prototype pollution via malicious INI file (CVE-2020-7788)\n\n* nodejs: use-after-free in the TLS implementation (CVE-2020-8265)\n\n* c-ares: ares_parse_{a,aaaa}_reply() insufficient naddrttls validation DoS (CVE-2020-8277)\n\n* nodejs-ajv: prototype pollution via crafted JSON schema in ajv.validate function (CVE-2020-15366)\n\n* nodejs: HTTP request smuggling via two copies of a header field in an http request (CVE-2020-8287)\n\nFor more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and other related information, refer to the CVE page(s) listed in the References section.\n\nBug Fix(es):\n\n* yarn install crashes with nodejs:14 on aarch64 (BZ#1916465)",
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2020-7754"},
					Value: map[string]interface{}{},
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
			vs := alma.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
			})
		})
	}
}
