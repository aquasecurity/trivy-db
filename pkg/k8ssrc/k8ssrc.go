package k8ssrc

import (
	"github.com/aquasecurity/trivy-db/pkg/k8ssrc/api"
	"github.com/aquasecurity/trivy-db/pkg/types"
)

type K8sSrc interface {
	Name() types.SourceID
	Update(dir string) (err error)
}

var (
	// All holds all data sources
	All = []K8sSrc{
		// Outdated API
		api.NewOutDatedAPI(),
	}
)
