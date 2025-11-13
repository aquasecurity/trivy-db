package julia_test

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/julia"
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
					Key: []string{
						"data-source",
						"julia::Julia Ecosystem Security Advisories",
					},
					Value: types.DataSource{
						ID:   vulnerability.Julia,
						Name: "Julia Ecosystem Security Advisories",
						URL:  "https://github.com/JuliaLang/SecurityAdvisories.jl",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2025-52479",
						"julia::Julia Ecosystem Security Advisories",
						"HTTP",
					},
					Value: types.Advisory{
						VendorIDs: []string{
							"GHSA-4g68-4pxg-mw93",
							"JLSEC-2025-1",
						},
						PatchedVersions: []string{
							"1.10.17",
						},
						VulnerableVersions: []string{
							"<1.10.17",
						},
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2025-52479",
						"julia",
					},
					Value: types.VulnerabilityDetail{
						Title:       "CR/LF injection in URIs.jl (also affects HTTP.jl)",
						Description: "### Description\n\nThe URIs.jl and HTTP.jl packages allowed the construction of URIs containing CR/LF characters. If user input was not otherwise escaped or protected, this can lead to a CRLF injection attack.\n\nWith this simple Julia code, you can inject a custom header named `Foo` with the value `bar`:\n\n```julia\nimport HTTP\n\nHTTP.get(\"http://localhost:1337/ HTTP/1.1\\r\\nFoo: bar\\r\\nbaz:\")\n```\n\nThe server will receive the request like this:\n\n```\n➜ ncat -klp 1337\nGET / HTTP/1.1\nFoo: bar <-- injected header!\nbaz: HTTP/1.1\nHost: locahost:1337\nAccept: */*\nUser-Agent: HTTP.jl/1.11.5\nContent-Length: 0\nAccept-Encoding: gzip\n```\n\n### Impact\n\nInject headers or inject data to the request body and cause “HTTP response splitting”.\n\n### Patches\n\nUsers of HTTP.jl should upgrade immediately to HTTP.jl v1.10.17. All prior versions are vulnerable.\n\nUsers of URIs.jl should upgrade immediately to URIs.jl v1.6.0. All prior versions are vulnerable.\n\nThe check for valid URIs is now in the URI.jl package, and the latest version of HTTP.jl incorporates that fix.\n\n### Workarounds\n\nManually validate any URIs before passing them on to functions in this package.\n\n### References\n\nFixed by: https://github.com/JuliaWeb/URIs.jl/pull/66 (which is available in URIs.jl v1.6.0).\n\n### Credits\n\nThanks to *splitline* from the DEVCORE Research Team for reporting this issue.",
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2025-52479",
					},
					Value: map[string]any{},
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
			wantErr: "json decode error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := julia.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
			})
		})
	}
}
