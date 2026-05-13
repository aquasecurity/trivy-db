package rootio

import (
	"fmt"
	"strings"

	"github.com/samber/oops"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
)

// rootioBucket wraps a base OS ecosystem bucket with the Root.io naming
// convention: "root.io {os} {version}" (e.g. "root.io alpine 3.18").
type rootioBucket struct {
	base       bucket.Bucket
	dataSource types.DataSource
}

func (r rootioBucket) Name() string                 { return fmt.Sprintf("root.io %s", r.base.Name()) }
func (r rootioBucket) Ecosystem() ecosystem.Type    { return r.base.Ecosystem() }
func (r rootioBucket) DataSource() types.DataSource { return r.dataSource }

// resolveBucket parses the suffix from a "Root:<os>:<version>" ecosystem string
// and returns the matching Root.io OS bucket. The OSV parser lowercases the raw
// ecosystem and splits on the first ":", so this function receives e.g.
// "alpine:3.18", "debian:11", "ubuntu:20.04". Non-OS Root.io ecosystems
// ("npm", "pypi", "maven", "go") have no version suffix and are rejected,
// causing the OSV parser to skip those entries — language-ecosystem support
// is out of scope for this source.
func resolveBucket(suffix string) (bucket.Bucket, error) {
	eco, version, ok := strings.Cut(suffix, ":")
	if !ok || version == "" {
		return nil, oops.With("ecosystem", suffix).Errorf("non-OS Root.io ecosystem")
	}

	ds := source
	ds.Name = fmt.Sprintf("%s (%s)", source.Name, eco)
	ds.BaseID = types.SourceID(eco)
	return newOSBucket(ecosystem.Type(eco), version, ds)
}

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
