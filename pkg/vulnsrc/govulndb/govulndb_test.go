package govulndb_test

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/govulndb"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
)

func TestVulnSrc_Update(t *testing.T) {
	tests := []struct {
		name       string
		dir        string
		wantValues []vulnsrctest.WantValues
		noBuckets  [][]string
		wantErr    string
	}{
		{
			name: "happy path",
			dir:  filepath.Join("testdata", "happy"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{
						"data-source",
						"go::The Go Vulnerability Database",
					},
					Value: types.DataSource{
						ID:   vulnerability.GoVulnDB,
						Name: "The Go Vulnerability Database",
						URL:  "https://pkg.go.dev/vuln/",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2023-45288",
						"go::The Go Vulnerability Database",
						"stdlib",
					},
					Value: types.Advisory{
						VendorIDs: []string{
							"GHSA-4v7x-pqxf-cx7m",
							"GO-2024-2687",
						},
						PatchedVersions: []string{
							"1.21.9",
							"1.22.2",
						},
						VulnerableVersions: []string{
							"<1.21.9",
							">=1.22.0-0, <1.22.2",
						},
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2023-45288",
						"govulndb",
					},
					Value: types.VulnerabilityDetail{
						Title:       "HTTP/2 CONTINUATION flood in net/http",
						Description: "An attacker may cause an HTTP/2 endpoint to read arbitrary amounts of header data by sending an excessive number of CONTINUATION frames.\n\nMaintaining HPACK state requires parsing and processing all HEADERS and CONTINUATION frames on a connection. When a request's headers exceed MaxHeaderBytes, no memory is allocated to store the excess headers, but they are still parsed.\n\nThis permits an attacker to cause an HTTP/2 endpoint to read arbitrary amounts of header data, all associated with a request which is going to be rejected. These headers can include Huffman-encoded data which is significantly more expensive for the receiver to decode than for an attacker to send.\n\nThe fix sets a limit on the amount of excess header frames we will process before closing a connection.",
						References: []string{
							"https://go.dev/issue/65051",
							"https://go.dev/cl/576155",
							"https://groups.google.com/g/golang-announce/c/YgW0sx8mN3M",
							"https://pkg.go.dev/vuln/GO-2024-2687",
						},
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2023-45288",
					},
					Value: map[string]interface{}{},
				},
			},
			noBuckets: [][]string{
				// We should save only stdlib packages
				{
					"advisory-detail",
					"CVE-2021-41803",
				},
				{
					"vulnerability-detail",
					"CVE-2021-41803",
				},
				{
					"vulnerability-id",
					"CVE-2021-41803",
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
			wantErr: "JSON decode error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := govulndb.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
				NoBuckets:  tt.noBuckets,
			})
		})
	}
}
