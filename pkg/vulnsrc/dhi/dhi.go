// Package dhi ingests Docker Hardened Images advisories in OSV format.
package dhi

import (
	"path/filepath"
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/samber/oops"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/osv"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const osvEcosystem = "Docker Hardened Images"

var dhiDir = filepath.Join("vuln-list", "dhi")

var dataSource = types.DataSource{
	ID:   vulnerability.DHI,
	Name: "Docker Hardened Images Advisories",
	URL:  "https://github.com/docker-hardened-images/advisories",
}

// NewVulnSrc returns the DHI OSV vulnerability source.
func NewVulnSrc() osv.OSV {
	return osv.New(dhiDir, vulnerability.DHI, map[ecosystem.Type]types.DataSource{
		ecosystem.DHI: dataSource,
	}, osv.WithBucketResolver(strings.ToLower(osvEcosystem), resolveBucket), osv.WithTransformer(&transformer{}), osv.WithEntryIDAsPrimary())
}

func resolveBucket(string) (bucket.Bucket, error) {
	// The release is encoded in each affected package PURL. Start with an
	// unversioned DHI bucket and replace it in PostParseAffected.
	return bucket.NewDHI("", "", dataSource), nil
}

type transformer struct{}

// PostParseAffected derives the DHI release and architecture from its package PURL.
func (*transformer) PostParseAffected(adv osv.Advisory, affected osv.Affected) (osv.Advisory, error) {
	p, err := packageurl.FromString(affected.Package.PURL)
	if err != nil {
		return osv.Advisory{}, oops.With("purl", affected.Package.PURL).Wrapf(err, "failed to parse DHI package PURL")
	}
	if p.Namespace != ecosystem.DHI.String() || (p.Type != packageurl.TypeApk && p.Type != packageurl.TypeDebian) {
		return osv.Advisory{}, oops.With("purl", affected.Package.PURL).Errorf("unsupported DHI package PURL")
	}

	release := qualifier(p, "os_version")
	if release == "" {
		return osv.Advisory{}, oops.With("purl", affected.Package.PURL).Errorf("DHI package PURL is missing os_version")
	}
	if osName := qualifier(p, "os_name"); osName != ecosystem.DHI.String() {
		return osv.Advisory{}, oops.With("purl", affected.Package.PURL).Errorf("DHI package PURL has invalid os_name")
	}
	lineage := map[string]string{packageurl.TypeApk: "alpine", packageurl.TypeDebian: "debian"}[p.Type]
	if distro := qualifier(p, "os_distro"); distro != lineage {
		return osv.Advisory{}, oops.With("purl", affected.Package.PURL).Errorf("DHI package PURL has invalid os_distro")
	}

	adv.Bucket = bucket.NewDHI(lineage, release, dataSource)
	if arch := qualifier(p, "arch"); arch != "" {
		adv.Arches = []string{arch}
	}
	return adv, nil
}

// TransformAdvisories leaves the parsed DHI advisories unchanged.
func (*transformer) TransformAdvisories(advs []osv.Advisory, _ osv.Entry) ([]osv.Advisory, error) {
	return advs, nil
}

func qualifier(p packageurl.PackageURL, key string) string {
	for _, q := range p.Qualifiers {
		if q.Key == key {
			return q.Value
		}
	}
	return ""
}
