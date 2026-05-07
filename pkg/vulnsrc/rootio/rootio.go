package rootio

import (
	"maps"
	"path/filepath"
	"sort"
	"strings"

	"github.com/samber/lo"
	"github.com/samber/oops"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/alpine"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/debian"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/osv"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/ubuntu"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

var (
	vulnsDir = filepath.Join("vuln-list", "rootio")

	source = types.DataSource{
		ID:   vulnerability.RootIO,
		Name: "Root.io Security Patches",
		URL:  "https://api.root.io/external/patch_feed",
	}
)

type VulnSrc struct{}

func NewVulnSrc() VulnSrc { return VulnSrc{} }

func (VulnSrc) Name() types.SourceID { return source.ID }

func (vs VulnSrc) Update(root string) error {
	eb := oops.In("rootio").With("root", root)

	o := osv.New(vulnsDir, source.ID, nil,
		osv.WithBucketResolver("root", resolveBucket),
	)
	if err := o.Update(root); err != nil {
		return eb.Wrapf(err, "failed to update Root.io vulnerability data")
	}
	return nil
}

type VulnSrcGetter struct {
	baseOS types.SourceID
	dbc    db.Operation
}

func NewVulnSrcGetter(baseOS types.SourceID) VulnSrcGetter {
	return VulnSrcGetter{
		baseOS: baseOS,
		dbc:    db.Config{},
	}
}

func (vs VulnSrcGetter) Get(params db.GetParams) ([]types.Advisory, error) {
	eb := oops.In("rootio").With("base_os", vs.baseOS).With("os_version", params.Release).With("package_name", params.PkgName)
	// Get advisories from the original distributors, like Debian or Alpine
	advs, err := vs.baseOSGetter().Get(params)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get advisories for base OS")
	}

	// Simulate the advisories with Root.io's version constraints
	allAdvs := make(map[string]types.Advisory, len(advs))
	for _, adv := range advs {
		if adv.FixedVersion != "" {
			adv.VulnerableVersions = []string{"<" + adv.FixedVersion}
			adv.PatchedVersions = []string{adv.FixedVersion}
			adv.FixedVersion = ""
		}
		allAdvs[adv.VulnerabilityID] = adv
	}

	bkt, err := newOSBucket(ecosystem.Type(strings.ToLower(string(vs.baseOS))), params.Release, source)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to build bucket")
	}
	advs, err = vs.dbc.GetAdvisories(bkt.Name(), params.PkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get advisories")
	}

	rootAdvs := lo.SliceToMap(advs, func(adv types.Advisory) (string, types.Advisory) {
		return adv.VulnerabilityID, adv
	})

	// On vulnerability-ID collision, Root.io's entry wins over the upstream's.
	maps.Copy(allAdvs, rootAdvs)

	if len(allAdvs) == 0 {
		return nil, nil
	}

	allAdvsSlice := lo.Values(allAdvs)
	sort.Slice(allAdvsSlice, func(i, j int) bool {
		return allAdvsSlice[i].VulnerabilityID < allAdvsSlice[j].VulnerabilityID
	})

	return allAdvsSlice, nil
}

func (vs VulnSrcGetter) baseOSGetter() db.Getter {
	switch vs.baseOS {
	case vulnerability.Debian:
		return debian.NewVulnSrc()
	case vulnerability.Ubuntu:
		return ubuntu.NewVulnSrc()
	case vulnerability.Alpine:
		return alpine.NewVulnSrc()
	}
	return nil
}
