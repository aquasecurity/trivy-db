package seal

import (
	"fmt"
	"path/filepath"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/osv"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/samber/oops"
)

const (
	platformFormat = "seal %s %s" // "seal {baseOS} {version}"
)

var (
	vulnsDir = filepath.Join("vuln-list", "seal")

	source = types.DataSource{
		ID:   vulnerability.Seal,
		Name: "Seal Security Database",
		URL:  "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
	}

	supportedEcosystems = []types.Ecosystem{
		vulnerability.AlpineEcosystem,
		vulnerability.CBLMarinerEcosystem,
		vulnerability.CentOSEcosystem,
		vulnerability.DebianEcosystem,
		vulnerability.OracleLinuxEcosystem,
		vulnerability.RedHatEcosystem,
		vulnerability.UbuntuEcosystem,
	}
)

type VulnSrc struct {
	supportedEcosystems []types.Ecosystem
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		supportedEcosystems: supportedEcosystems,
	}
}

func (VulnSrc) Name() types.SourceID {
	return vulnerability.Seal
}

func (vs VulnSrc) Update(root string) error {
	eb := oops.In("seal").With("file_path", root)
	dataSources := map[types.Ecosystem]types.DataSource{}
	for _, ecosystem := range vs.supportedEcosystems {
		dataSources[ecosystem] = source
	}

	if err := osv.New(vulnsDir, source.ID, dataSources, osv.WithBucketNameFunc(bucketName)).Update(root); err != nil {
		return eb.Wrapf(err, "failed to update Seal vulnerability data")
	}

	return nil
}

func bucketName(ecosystem osv.Ecosystem, _ string) string {
	return fmt.Sprintf(platformFormat, ecosystem.Name, ecosystem.Version)
}

type VulnSrcGetter struct {
	baseOS types.SourceID
	dbc    db.Operation
	logger *log.Logger
}

func NewVulnSrcGetter(baseOS types.SourceID) VulnSrcGetter {
	return VulnSrcGetter{
		baseOS: baseOS,
		dbc:    db.Config{},
		logger: log.WithPrefix(fmt.Sprintf("seal-%s", baseOS)),
	}
}

func (vs VulnSrcGetter) Get(params db.GetParams) ([]types.Advisory, error) {
	eb := oops.In("seal").With("base_os", vs.baseOS).With("os_version", params.Release).With("package_name", params.PkgName)

	sealOSVer := fmt.Sprintf(platformFormat, vs.baseOS, params.Release)
	advs, err := vs.dbc.GetAdvisories(sealOSVer, params.PkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get advisories for base OS")
	}
	return advs, nil
}
