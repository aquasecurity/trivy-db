package julia

import (
	"strings"

	"github.com/samber/lo"

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

	return osv.New(juliaDir, sourceID, dataSources, osv.WithTransformer(&transformer{})).Update(root)
}

type transformer struct {
}

func (t *transformer) PostParseAffected(adv osv.Advisory, _ osv.Affected) (osv.Advisory, error) {
	// We will save aliases as VendorIDs, so for Julia, we only keep JLSEC-* aliases.
	adv.Aliases = lo.Filter(adv.Aliases, func(alias string, _ int) bool {
		return strings.HasPrefix(alias, "JLSEC")
	})
	return adv, nil
}

func (t *transformer) TransformAdvisories(advisories []osv.Advisory, _ osv.Entry) ([]osv.Advisory, error) {
	return advisories, nil
}
