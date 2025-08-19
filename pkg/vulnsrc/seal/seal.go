package seal

import (
	"fmt"
	"path/filepath"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/osv"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	sourceID = vulnerability.Seal
)

var vulnsDir = filepath.Join("vuln-list", "seal")

type VulnSrc struct{}

func NewVulnSrc() VulnSrc {
	return VulnSrc{}
}

func (VulnSrc) Name() types.SourceID {
	return sourceID
}

func (VulnSrc) Update(root string) error {
	dataSources := map[types.Ecosystem]types.DataSource{}
	for _, ecosystem := range vulnerability.Ecosystems {
		dataSources[ecosystem] = types.DataSource{
			ID:   sourceID,
			Name: "Seal Security Database",
			URL:  "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
		}
	}

	return osv.New(vulnsDir, sourceID, dataSources, osv.WithBucketNameFunc(bucketName)).Update(root)
}

func bucketName(ecosystem osv.Ecosystem, _ string) string {
	return fmt.Sprintf("%s %s %s", sourceID, ecosystem.Name, ecosystem.Version)
}
