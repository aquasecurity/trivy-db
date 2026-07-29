// Package chainguard stores the vulnerability data Chainguard publishes for the
// packages in its own APK repository.
//
// The advisories come from Chainguard's OSV v3 feed, which replaced the
// deprecated secdb (security.json) feed. Parsing is shared with Wolfi in the
// chainguardosv package, since both ecosystems are published in the same feed.
package chainguard

import (
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/chainguardosv"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

var ecosystem = chainguardosv.Ecosystem{
	Name:   "Chainguard",
	Dir:    "chainguard",
	Bucket: bucket.NewChainguard(""),
	Source: types.DataSource{
		ID:   vulnerability.Chainguard,
		Name: "Chainguard Security Data",
		URL:  "https://advisories.cgr.dev/chainguard/v3/osv/all.json",
	},
}

// VulnSrc stores Chainguard advisories.
type VulnSrc = chainguardosv.VulnSrc

// NewVulnSrc is the factory method for the Chainguard data source.
func NewVulnSrc() VulnSrc {
	return chainguardosv.NewVulnSrc(ecosystem)
}
