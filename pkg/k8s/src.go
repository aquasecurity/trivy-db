package k8s

import (
	"github.com/aquasecurity/trivy-db/pkg/k8s/api"
	"github.com/aquasecurity/trivy-db/pkg/types"
)

type Src interface {
	Name() types.SourceID
	Update(dir string) (err error)
}

var (
	// All holds all data sources
	All = []Src{
		// Outdated API
		api.NewOutdated(),
	}
)
