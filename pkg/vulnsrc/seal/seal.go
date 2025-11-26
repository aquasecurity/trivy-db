package seal

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/samber/oops"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/osv"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

var (
	vulnsDir = filepath.Join("vuln-list", "seal")

	source = types.DataSource{
		ID:   vulnerability.Seal,
		Name: "Seal Security Database",
		URL:  "http://vulnfeed.sealsecurity.io/v1/osv/renamed/vulnerabilities.zip",
	}
)

// resolveBucket creates a seal bucket from base ecosystem suffix
func resolveBucket(suffix string) (bucket.Bucket, error) {
	var eco ecosystem.Type
	// Separate base ecosystem and version (if exists)
	// e.g. "Alpine", "Red Hat:8", "Debian"
	baseEco, ver, _ := strings.Cut(suffix, ":")
	switch baseEco {
	case "alpine":
		eco = ecosystem.Alpine
		source.BaseID = vulnerability.Alpine
	case "debian":
		eco = ecosystem.Debian
		source.BaseID = vulnerability.Debian
	case "red hat":
		eco = ecosystem.RedHat
		source.BaseID = vulnerability.RedHat
	default:
		return nil, oops.With("ecosystem", "seal").With("base", suffix).Errorf("unsupported base ecosystem")
	}

	return newBucket(eco, ver, source)
}

type VulnSrc struct {
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{}
}

func (VulnSrc) Name() types.SourceID {
	return vulnerability.Seal
}

func (vs VulnSrc) Update(root string) error {
	eb := oops.In("seal").With("file_path", root)

	sources := map[ecosystem.Type]types.DataSource{
		ecosystem.Seal: source,
	}

	if err := osv.New(vulnsDir, source.ID, sources,
		osv.WithBucketResolver("seal", resolveBucket)).Update(root); err != nil {
		return eb.Wrapf(err, "failed to update Seal vulnerability data")
	}

	return nil
}

type VulnSrcGetter struct {
	baseEcosystem ecosystem.Type
	dbc           db.Operation
	logger        *log.Logger
}

func NewVulnSrcGetter(baseEcosystem ecosystem.Type) VulnSrcGetter {
	return VulnSrcGetter{
		baseEcosystem: baseEcosystem,
		dbc:           db.Config{},
		logger:        log.WithPrefix(fmt.Sprintf("seal-%s", baseEcosystem)),
	}
}

func (vs VulnSrcGetter) Get(params db.GetParams) ([]types.Advisory, error) {
	eb := oops.In("seal").With("base_ecosystem", vs.baseEcosystem).With("os_version", params.Release).With("package_name", params.PkgName)

	bkt, err := newBucket(vs.baseEcosystem, params.Release, types.DataSource{})
	if err != nil {
		return nil, eb.Wrapf(err, "failed to create a bucket name")
	}
	advs, err := vs.dbc.GetAdvisories(bkt.Name(), params.PkgName)

	var splitAdvs []types.Advisory
	for _, adv := range advs {
		sadvs, err := splitAdvisoriesByRanges(adv)
		if err != nil {
			return nil, eb.Wrapf(err, "failed to split advisories by ranges")
		}
		splitAdvs = append(splitAdvs, sadvs...)
	}
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get advisories for base OS")
	}
	return splitAdvs, nil
}

// splitAdvisoriesByRanges splits advisories if there are multiple vulnerable version ranges
// e.g. VulnerableVersions: [">=1.0, <1.5", ">=2.0, <2.5"], PatchedVersions: ["1.5", "2.5"]
// will be split into two advisories:
// 1. VulnerableVersions: [">=1.0, <1.5"], PatchedVersions: ["1.5"]
// 2. VulnerableVersions: [">=2.0, <2.5"], PatchedVersions: ["2.5"]
func splitAdvisoriesByRanges(advisory types.Advisory) ([]types.Advisory, error) {
	if len(advisory.VulnerableVersions) == 1 {
		return []types.Advisory{
			advisory,
		}, nil
	}

	var advs []types.Advisory
	for i, vr := range advisory.VulnerableVersions {
		pv := advisory.PatchedVersions[i]

		// In the `osv` package, we populate vulnerable and fixed versions when a `fixed` event is detected
		// Therefore, the order of versions in these slices must be the same
		if !strings.Contains(vr, pv) {
			return nil, oops.With("vulnerable version", vr).With("patched version", pv).
				Errorf("vulnerable version range should contain the patched version")
		}

		adv := advisory
		adv.VulnerableVersions = []string{vr}
		adv.PatchedVersions = []string{pv}
		advs = append(advs, adv)
	}

	return advs, nil
}
