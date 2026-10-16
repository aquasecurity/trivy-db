package dhi_test

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/dhi"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
)

func TestVulnSrc_Update(t *testing.T) {
	vs := dhi.NewVulnSrc()
	vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
		Dir: filepath.Join("testdata", "happy"),
		WantValues: []vulnsrctest.WantValues{
			{
				Key: []string{"data-source", "dhi alpine 3.24"},
				Value: types.DataSource{
					ID: vulnerability.DHI, Name: "Docker Hardened Images Advisories",
					URL: "https://github.com/docker-hardened-images/advisories",
				},
			},
			{
				Key: []string{"advisory-detail", "DHI-CVE-2016-2781-coreutils", "dhi alpine 3.24", "coreutils"},
				Value: types.Advisory{
					VendorIDs: []string{"CVE-2016-2781"}, VulnerableVersions: []string{"<9.11-r1"},
					PatchedVersions: []string{"9.11-r1"}, Arches: []string{"aarch64"},
				},
			},
		},
	})
}
