package echoosv

import (
	"fmt"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
)

// echoBucket wraps a standard language bucket and prepends "echo " to its name.
// This ensures advisories are stored under supplier-specific buckets such as
// "echo pip::Echo OSV", matching the trivy scanner's "echo <ecosystem>::" query.
type echoBucket struct {
	base       bucket.Bucket
	dataSource types.DataSource
}

func (e echoBucket) Name() string {
	return fmt.Sprintf("echo %s", e.base.Name())
}

func (e echoBucket) Ecosystem() ecosystem.Type {
	return e.base.Ecosystem()
}

func (e echoBucket) DataSource() types.DataSource {
	return e.dataSource
}

// newEchoBucket wraps a standard language bucket so that its name gets the "echo " prefix.
func newEchoBucket(newBase func(types.DataSource) (bucket.DataSourceBucket, error),
	dataSource types.DataSource) (bucket.Bucket, error) {
	base, err := newBase(dataSource)
	if err != nil {
		return nil, err
	}
	return echoBucket{
		base:       base,
		dataSource: dataSource,
	}, nil
}
