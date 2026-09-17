package rapidfort

import (
	"strings"

	"github.com/samber/oops"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

// rapidFortBucket names a bucket after the base OS bucket it wraps: "rapidfort ubuntu 22.04", or "rapidfort ubuntu" for the version-less rebuilds.
type rapidFortBucket struct {
	base       bucket.Bucket
	dataSource types.DataSource
}

func (r rapidFortBucket) Name() string {
	// Some base buckets append the version unconditionally, so a version-less
	// rebuild comes back with a trailing space ("Oracle Linux "). Trim it so
	// every distro spells its rebuild bucket the same way.
	return strings.TrimRight("rapidfort "+r.base.Name(), " ")
}

func (r rapidFortBucket) Ecosystem() ecosystem.Type {
	return r.base.Ecosystem()
}

func (r rapidFortBucket) DataSource() types.DataSource {
	return r.dataSource
}

// newBucket builds a RapidFort bucket for the given base ecosystem and version, failing for an ecosystem RapidFort doesn't ship advisories for.
func newBucket(baseEcosystem ecosystem.Type, version string) (bucket.DataSourceBucket, error) {
	ds := source
	var base bucket.Bucket
	switch baseEcosystem {
	case ecosystem.Ubuntu:
		base, ds.BaseID = bucket.NewUbuntu(version), vulnerability.Ubuntu
	case ecosystem.Debian:
		base, ds.BaseID = bucket.NewDebian(version), vulnerability.Debian
	case ecosystem.Alpine:
		base, ds.BaseID = bucket.NewAlpine(version), vulnerability.Alpine
	case ecosystem.RedHat:
		base, ds.BaseID = bucket.NewRedHat(version), vulnerability.RedHat
	case ecosystem.OracleLinux:
		base, ds.BaseID = bucket.NewOracle(version), vulnerability.OracleOVAL
	case ecosystem.Rocky:
		base, ds.BaseID = bucket.NewRocky(version), vulnerability.Rocky
	case ecosystem.AlmaLinux:
		base, ds.BaseID = bucket.NewAlma(version), vulnerability.Alma
	case ecosystem.AmazonLinux:
		base, ds.BaseID = bucket.NewAmazon(version), vulnerability.Amazon
	case ecosystem.Fedora:
		base, ds.BaseID = bucket.NewFedora(version), vulnerability.Fedora
	default:
		return nil, oops.With("base_ecosystem", baseEcosystem).Errorf("unsupported base ecosystem")
	}
	return rapidFortBucket{base: base, dataSource: ds}, nil
}
