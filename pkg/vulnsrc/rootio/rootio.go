package rootio

import (
	"encoding/json"
	"fmt"
	"maps"
	"path/filepath"
	"sort"
	"strings"

	"github.com/samber/lo"
	"github.com/samber/oops"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/alpine"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/debian"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/osv"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/ubuntu"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const platformFormat = "root.io %s %s" // "root.io {baseOS} {version}"

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

	dataSources := map[ecosystem.Type]types.DataSource{
		ecosystem.Npm:      source,
		ecosystem.Pip:      source,
		ecosystem.RubyGems: source,
	}

	o := osv.New(vulnsDir, source.ID, dataSources,
		osv.WithBucketResolver("alpine", resolveAlpineBucket),
		osv.WithBucketResolver("debian", resolveDebianBucket),
		osv.WithBucketResolver("ubuntu", resolveUbuntuBucket),
		osv.WithTransformer(&transformer{}),
	)
	if err := o.Update(root); err != nil {
		return eb.Wrapf(err, "failed to update Root.io vulnerability data")
	}
	return nil
}

// resolveAlpineBucket returns a placeholder Root.io Alpine bucket. The distro
// version is unknown at this point — TransformAdvisories rebuilds the bucket
// once it has read entry.DatabaseSpecific.
func resolveAlpineBucket(_ string) (bucket.Bucket, error) {
	return rootioBucket{base: bucket.NewAlpine(""), dataSource: source}, nil
}

func resolveDebianBucket(_ string) (bucket.Bucket, error) {
	return rootioBucket{base: bucket.NewDebian(""), dataSource: source}, nil
}

func resolveUbuntuBucket(_ string) (bucket.Bucket, error) {
	return rootioBucket{base: bucket.NewUbuntu(""), dataSource: source}, nil
}

type transformer struct{}

func (t *transformer) PostParseAffected(adv osv.Advisory, _ osv.Affected) (osv.Advisory, error) {
	return adv, nil
}

// TransformAdvisories applies Root.io's distro/distro_version (carried in
// entry.DatabaseSpecific) to OS advisories and drops entries that have no
// fixed version.
func (t *transformer) TransformAdvisories(advs []osv.Advisory, entry osv.Entry) ([]osv.Advisory, error) {
	var dbSpec struct {
		Distro        string `json:"distro"`
		DistroVersion string `json:"distro_version"`
	}
	if len(entry.DatabaseSpecific) > 0 {
		if err := json.Unmarshal(entry.DatabaseSpecific, &dbSpec); err != nil {
			return nil, oops.With("entry_id", entry.ID).Wrapf(err, "failed to decode database_specific")
		}
	}

	out := make([]osv.Advisory, 0, len(advs))
	for _, adv := range advs {
		// Drop advisories without a fixed version.
		if len(adv.PatchedVersions) == 0 {
			continue
		}

		if dbSpec.Distro != "" {
			ds := source
			ds.Name = source.Name + fmt.Sprintf(" (%s)", dbSpec.Distro)
			ds.BaseID = types.SourceID(dbSpec.Distro)

			bkt, err := newOSBucket(ecosystem.Type(strings.ToLower(dbSpec.Distro)), dbSpec.DistroVersion, ds)
			if err != nil {
				return nil, oops.With("entry_id", entry.ID).Wrapf(err, "failed to build bucket")
			}
			adv.Bucket = bkt
		}
		out = append(out, adv)
	}
	return out, nil
}

type config struct {
	dbc    db.Operation
	logger *log.Logger
}

type VulnSrcGetter struct {
	baseOS types.SourceID
	config
}

func NewVulnSrcGetter(baseOS types.SourceID) VulnSrcGetter {
	return VulnSrcGetter{
		baseOS: baseOS,
		config: config{
			dbc:    db.Config{},
			logger: log.WithPrefix(fmt.Sprintf("rootio-%s", baseOS)),
		},
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
			adv.FixedVersion = "" // Clear fixed version to avoid confusion
		}
		allAdvs[adv.VulnerabilityID] = adv
	}

	rootioOSVer := fmt.Sprintf(platformFormat, vs.baseOS, params.Release)
	advs, err = vs.dbc.GetAdvisories(rootioOSVer, params.PkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get advisories")
	}

	rootAdvs := lo.SliceToMap(advs, func(adv types.Advisory) (string, types.Advisory) {
		return adv.VulnerabilityID, adv
	})

	// Merge the advisories from the original distributors with Root.io's advisories.
	// If both have the same vulnerability ID - only Root.io recommendation will be kept.
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
