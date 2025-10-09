package rootio

import (
	"fmt"

	"github.com/samber/oops"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
)

const bucketFormat = "root.io %s"

// rootioBucket for Root.io ecosystem with special naming convention
type rootioBucket struct {
	baseOSBucket      bucket.Bucket
	languageEcosystem ecosystem.Type
}

func (s rootioBucket) Name() string {
	if s.baseOSBucket != nil {
		return fmt.Sprintf(bucketFormat, s.baseOSBucket.Name())
	}
	return fmt.Sprintf(bucketFormat, s.languageEcosystem)
}

func (s rootioBucket) Ecosystem() ecosystem.Type {
	if s.baseOSBucket != nil {
		return s.baseOSBucket.Ecosystem()
	}
	return s.languageEcosystem
}

// newBucket creates a bucket for Root.io ecosystem
func newBucket(baseEco ecosystem.Type, baseEcoVer string) (bucket.Bucket, error) {
	bkt := rootioBucket{}
	switch baseEco {
	// OS ecosystems
	case ecosystem.Alpine:
		bkt.baseOSBucket = bucket.NewAlpine(baseEcoVer)
	case ecosystem.Debian:
		bkt.baseOSBucket = bucket.NewDebian(baseEcoVer)
	case ecosystem.Ubuntu:
		bkt.baseOSBucket = bucket.NewUbuntu(baseEcoVer)
	case ecosystem.Pip, ecosystem.Npm, ecosystem.RubyGems, ecosystem.Maven, ecosystem.Go, ecosystem.NuGet, ecosystem.Cargo:
		bkt.languageEcosystem = baseEco
	default:
		return nil, oops.With("base", baseEco).Errorf("unsupported base ecosystem for Root.io bucket")
	}

	return bkt, nil
}
