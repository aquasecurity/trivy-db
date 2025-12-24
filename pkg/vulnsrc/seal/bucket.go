package seal

import (
	"fmt"

	"github.com/samber/oops"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
)

// sealBucket for Seal ecosystem with special naming convention
type sealBucket struct {
	base       bucket.Bucket
	dataSource types.DataSource
}

func (s sealBucket) Name() string {
	return fmt.Sprintf("seal %s", s.base.Name())
}

func (s sealBucket) Ecosystem() ecosystem.Type {
	return s.base.Ecosystem()
}

func (s sealBucket) DataSource() types.DataSource {
	return s.dataSource
}

// newBucket creates a bucket for Seal ecosystem
func newBucket(baseEco ecosystem.Type, baseEcoVer string, dataSource types.DataSource) (bucket.Bucket, error) {
	bkt := sealBucket{
		dataSource: dataSource,
	}

	var err error
	switch baseEco {
	case ecosystem.Alpine:
		bkt.base = bucket.NewAlpine("")
	case ecosystem.Debian:
		bkt.base = bucket.NewDebian("")
	case ecosystem.RedHat:
		bkt.base = bucket.NewRedHat(baseEcoVer)
	case ecosystem.Maven:
		bkt.base, err = bucket.NewMaven(dataSource)
	case ecosystem.Pip:
		bkt.base, err = bucket.NewPyPI(dataSource)
	case ecosystem.Npm:
		bkt.base, err = bucket.NewNpm(dataSource)
	case ecosystem.Go:
		bkt.base, err = bucket.NewGo(dataSource)
	default:
		return nil, oops.With("base", baseEco).Errorf("unsupported base ecosystem for Seal bucket")
	}

	if err != nil {
		return nil, oops.Wrapf(err, "failed to initialize seal language bucket")
	}

	return bkt, nil
}
