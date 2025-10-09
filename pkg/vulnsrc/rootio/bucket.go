package rootio

import (
	"fmt"

	"github.com/samber/oops"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const bucketFormat = "root.io %s"

var rootioDataSource = types.DataSource{
	ID:   vulnerability.RootIO,
	Name: "Root.io Security Patches",
	URL:  "https://api.root.io/external/patch_feed",
}

// rootioBucket for Root.io ecosystem with special naming convention
type rootioBucket struct {
	baseOSBucket   bucket.Bucket
	languageBucket bucket.DataSourceBucket
}

func (s rootioBucket) Name() string {
	if s.baseOSBucket != nil {
		return fmt.Sprintf(bucketFormat, s.baseOSBucket.Name())
	}
	if s.languageBucket != nil {
		return s.languageBucket.Name()
	}
	return ""
}

func (s rootioBucket) Ecosystem() ecosystem.Type {
	if s.baseOSBucket != nil {
		return s.baseOSBucket.Ecosystem()
	}
	if s.languageBucket != nil {
		return s.languageBucket.Ecosystem()
	}
	return ""
}

// newBucket creates a bucket for Root.io ecosystem
func newBucket(baseEco ecosystem.Type, baseEcoVer string) (bucket.Bucket, error) {
	bkt := rootioBucket{}
	var err error
	switch baseEco {
	// Supported OS ecosystems
	case ecosystem.Alpine:
		bkt.baseOSBucket = bucket.NewAlpine(baseEcoVer)
	case ecosystem.Debian:
		bkt.baseOSBucket = bucket.NewDebian(baseEcoVer)
	case ecosystem.Ubuntu:
		bkt.baseOSBucket = bucket.NewUbuntu(baseEcoVer)
	// Supported language ecosystems - use standard bucket format
	case ecosystem.Pip:
		bkt.languageBucket, err = bucket.NewPyPI(rootioDataSource)
	case ecosystem.Npm:
		bkt.languageBucket, err = bucket.NewNpm(rootioDataSource)
	case ecosystem.RubyGems:
		bkt.languageBucket, err = bucket.NewRubyGems(rootioDataSource)
	case ecosystem.Maven:
		bkt.languageBucket, err = bucket.NewMaven(rootioDataSource)
	case ecosystem.Go:
		bkt.languageBucket, err = bucket.NewGo(rootioDataSource)
	case ecosystem.NuGet:
		bkt.languageBucket, err = bucket.NewNuGet(rootioDataSource)
	case ecosystem.Cargo:
		bkt.languageBucket, err = bucket.NewCargo(rootioDataSource)
	default:
		return nil, oops.With("base", baseEco).Errorf("unsupported base ecosystem for Root.io bucket")
	}

	if err != nil {
		return nil, oops.Wrapf(err, "failed to create bucket for %s", baseEco)
	}

	return bkt, nil
}
