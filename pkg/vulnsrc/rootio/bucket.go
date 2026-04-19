package rootio

import (
	"fmt"

	"github.com/samber/oops"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
)

// rootioBucket wraps a base ecosystem bucket with the Root.io naming convention.
// For OS ecosystems the name is prefixed with "root.io " (e.g. "root.io alpine 3.18").
// For app ecosystems the base name is used unchanged (e.g. "npm").
type rootioBucket struct {
	base       bucket.Bucket
	dataSource types.DataSource
}

func (r rootioBucket) Name() string {
	switch r.base.Ecosystem() {
	case ecosystem.Alpine, ecosystem.Debian, ecosystem.Ubuntu:
		return fmt.Sprintf("root.io %s", r.base.Name())
	}
	return r.base.Name()
}

func (r rootioBucket) Ecosystem() ecosystem.Type    { return r.base.Ecosystem() }
func (r rootioBucket) DataSource() types.DataSource { return r.dataSource }

// newOSBucket creates a Root.io bucket for an OS ecosystem with the distro version applied.
func newOSBucket(baseEco ecosystem.Type, version string, ds types.DataSource) (bucket.Bucket, error) {
	var b bucket.Bucket
	switch baseEco {
	case ecosystem.Alpine:
		b = bucket.NewAlpine(version)
	case ecosystem.Debian:
		b = bucket.NewDebian(version)
	case ecosystem.Ubuntu:
		b = bucket.NewUbuntu(version)
	default:
		return nil, oops.With("base", baseEco).Errorf("unsupported base ecosystem for Root.io bucket")
	}
	return rootioBucket{base: b, dataSource: ds}, nil
}
