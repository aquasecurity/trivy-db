package seal

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/samber/oops"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/osv"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	platformFormat = "seal %s" // "seal {baseOS}" e.g. "seal redhat 9" or "seal alpine"
)

var (
	vulnsDir = filepath.Join("vuln-list", "seal")

	source = types.DataSource{
		ID:   vulnerability.Seal,
		Name: "Seal Security Database",
		URL:  "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
	}

	supportedOSes = map[string]types.SourceID{
		"alpine":    vulnerability.Alpine,
		"debian":    vulnerability.Debian,
		"red hat:6": vulnerability.RedHat,
		"red hat:7": vulnerability.RedHat,
		"red hat:8": vulnerability.RedHat,
		"red hat:9": vulnerability.RedHat,
	}
)

type VulnSrc struct {
	supportedOSes map[string]types.SourceID
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		supportedOSes: supportedOSes,
	}
}

func (VulnSrc) Name() types.SourceID {
	return vulnerability.Seal
}

func (vs VulnSrc) Update(root string) error {
	eb := oops.In("seal").With("file_path", root)
	dataSources := map[osv.Ecosystem]types.DataSource{}
	for suffix, baseOS := range vs.supportedOSes {
		s := source
		s.BaseID = baseOS

		osvEcosystem := osv.Ecosystem{
			Name:   vulnerability.SealEcosystemName,
			Suffix: suffix,
		}
		dataSources[osvEcosystem] = s
	}

	if err := osv.New(vulnsDir, source.ID, dataSources, osv.WithBucketNameFunc(vs.bucketName)).Update(root); err != nil {
		return eb.Wrapf(err, "failed to update Seal vulnerability data")
	}

	return nil
}

func (VulnSrc) bucketName(ecosystem osv.Ecosystem, _ string) string {
	suffix := strings.ReplaceAll(strings.ToLower(ecosystem.Suffix), " ", "")
	baseOS, version, _ := strings.Cut(suffix, ":")
	return bucketName(baseOS, version)
}

func bucketName(baseOS, version string) string {
	if version != "" {
		baseOS = baseOS + " " + version
	}
	return fmt.Sprintf(platformFormat, baseOS)
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

	sealOSVer := bucketName(string(vs.baseOS), params.Release)
	advs, err := vs.dbc.GetAdvisories(sealOSVer, params.PkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get advisories for base OS")
	}
	return advs, nil
}
