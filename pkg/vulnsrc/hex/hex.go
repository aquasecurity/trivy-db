package hex

import (
	"path/filepath"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/osv"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const sourceID = vulnerability.OSV

var hexDir = filepath.Join("vuln-list", "osv", "hex")

type VulnSrc struct{}

func NewVulnSrc() VulnSrc {
	return VulnSrc{}
}

func (VulnSrc) Name() types.SourceID {
	return sourceID
}

func (VulnSrc) Update(root string) error {
	dataSources := map[ecosystem.Type]types.DataSource{
		ecosystem.Erlang: {
			ID:   sourceID,
			Name: "Open Source Vulnerabilities (Hex)",
			URL:  "https://osv.dev/list?ecosystem=Hex",
		},
	}

	return osv.New(hexDir, sourceID, dataSources).Update(root)
}
