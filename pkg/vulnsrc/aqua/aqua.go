package aqua

import (
	"path/filepath"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/osv"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const sourceID = vulnerability.Aqua

var vulnsDir = filepath.Join("vuln-list-aqua", "vulns")

// all contains all supported ecosystems for Aqua Security database
var all = []ecosystem.Type{
	ecosystem.Npm,
	ecosystem.Composer,
	ecosystem.Pip,
	ecosystem.RubyGems,
	ecosystem.Cargo,
	ecosystem.Julia,
	ecosystem.NuGet,
	ecosystem.Maven,
	ecosystem.Go,
	ecosystem.Conan,
	ecosystem.Erlang,
	ecosystem.Pub,
	ecosystem.Swift,
	ecosystem.Cocoapods,
	ecosystem.Bitnami,
	ecosystem.Kubernetes,
}

type VulnSrc struct{}

func NewVulnSrc() VulnSrc {
	return VulnSrc{}
}

func (VulnSrc) Name() types.SourceID {
	return sourceID
}

func (VulnSrc) Update(root string) error {
	dataSources := map[ecosystem.Type]types.DataSource{}
	for _, eco := range all {
		dataSources[eco] = types.DataSource{
			ID:   sourceID,
			Name: "The Aqua Security Vulnerability Database",
			URL:  "https://github.com/aquasecurity/vuln-list-aqua",
		}
	}

	return osv.New(vulnsDir, sourceID, dataSources).Update(root)
}
