package azure

import (
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/mariner"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

var (
	ErrNotSupported = xerrors.New("format not supported")
)

func NewVulnSrc() mariner.VulnSrc {
	return mariner.VulnSrc{
		Dbc:         db.Config{},
		VulnListDir: filepath.Join("azure"),
		Source: types.DataSource{
			ID:   vulnerability.AzureLinux,
			Name: "Azure Linux Vulnerability Data",
			URL:  "https://github.com/microsoft/AzureLinuxVulnerabilityData",
		},
		PlatformFormat: "Azure Linux %s",
	}
}
