package azure

import (
	"path/filepath"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

func NewMarinerVulnSrc() VulnSrc {
	return VulnSrc{
		Dbc:      db.Config{},
		AzureDir: filepath.Join("mariner"),
		Source: types.DataSource{
			ID:   vulnerability.CBLMariner,
			Name: "CBL-Mariner Vulnerability Data",
			URL:  "https://github.com/microsoft/CBL-MarinerVulnerabilityData",
		},
		PlatformFormat: "CBL-Mariner %s",
	}
}
