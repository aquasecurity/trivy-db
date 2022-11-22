package wolfi

import (
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/alpine"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	wolfiDir       = "wolfi"
	platformFormat = "wolfi%s"
)

var (
	source = types.DataSource{
		ID:   vulnerability.Wolfi,
		Name: "Wolfi security databases",
		URL:  "https://packages.wolfi.dev/os/security.json",
	}
)

func NewVulnSrc() alpine.VulnSrc {
	return alpine.NewVulnSrc(
		alpine.WithDir(wolfiDir),
		alpine.WithSource(source),
		alpine.WithPlatformFormat(platformFormat))
}
