package julia

import (
	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/osv"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	sourceID = vulnerability.Julia
	juliaDir = "julia"
)

type VulnDB struct{}

func NewVulnSrc() VulnDB {
	return VulnDB{}
}

func (VulnDB) Name() types.SourceID {
	return sourceID
}

func (VulnDB) Update(root string) error {
	dataSources := map[ecosystem.Type]types.DataSource{
		ecosystem.Julia: {
			ID:   sourceID,
			Name: "Julia Ecosystem Security Advisories",
			URL:  "https://github.com/JuliaLang/SecurityAdvisories.jl",
		},
	}

	return osv.New(juliaDir, sourceID, dataSources).Update(root)
}
