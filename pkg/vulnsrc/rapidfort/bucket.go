package rapidfort

import (
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
	return "rapidfort " + r.base.Name()
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
	case ecosystem.Alpine:
		base, ds.BaseID = bucket.NewAlpine(version), vulnerability.Alpine
	case ecosystem.RedHat:
		base, ds.BaseID = bucket.NewRedHat(version), vulnerability.RedHat
	case ecosystem.Fedora:
		base, ds.BaseID = bucket.NewFedora(version), vulnerability.Fedora
	default:
		return nil, oops.With("base_ecosystem", baseEcosystem).Errorf("unsupported base ecosystem")
	}
	return rapidFortBucket{base: base, dataSource: ds}, nil
}
