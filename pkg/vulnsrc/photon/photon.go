package photon

import (
	"path/filepath"

	"github.com/aquasecurity/trivy-db/pkg/db"
)

const (
	photonDir      = "photon"
	platformFormat = "Photon OS %s"
)

type VulnSrc struct {
	dbc db.Operations
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", photonDir)

	var cves []PhotonCVE
}
