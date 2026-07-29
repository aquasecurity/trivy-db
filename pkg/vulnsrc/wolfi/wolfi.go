// Package wolfi stores the vulnerability data Chainguard publishes for the
// packages in the Wolfi APK repository.
//
// The advisories come from Chainguard's OSV v3 feed, which replaced the
// deprecated secdb (security.json) feed. Wolfi packages appear in that feed
// under the Wolfi ecosystem with the same version ranges as their Chainguard
// counterparts, so the two variants of an image report the same
// vulnerabilities. Parsing is shared with Chainguard in the chainguardosv
// package.
package wolfi

import (
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/chainguardosv"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

var ecosystem = chainguardosv.Ecosystem{
	Name:   "Wolfi",
	Dir:    "wolfi",
	Bucket: bucket.NewWolfi(""),
	Source: types.DataSource{
		ID:   vulnerability.Wolfi,
		Name: "Wolfi Security Data",
		URL:  "https://advisories.cgr.dev/chainguard/v3/osv/all.json",
	},
}

// VulnSrc stores Wolfi advisories.
type VulnSrc = chainguardosv.VulnSrc

// NewVulnSrc is the factory method for the Wolfi data source.
func NewVulnSrc() VulnSrc {
	return chainguardosv.NewVulnSrc(ecosystem)
}
