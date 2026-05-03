package echoosv

import (
	"path/filepath"
	"strings"

	"github.com/samber/oops"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/osv"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

var (
	vulnsDir = filepath.Join("vuln-list", "echo-osv")

	source = types.DataSource{
		ID:   vulnerability.EchoOSV,
		Name: "Echo OSV",
		URL:  "https://advisory.echohq.com/osv",
	}
)

type VulnSrc struct{}

func NewVulnSrc() VulnSrc {
	return VulnSrc{}
}

func (VulnSrc) Name() types.SourceID {
	return source.ID
}

func (VulnSrc) Update(root string) error {
	dataSources := map[ecosystem.Type]types.DataSource{
		ecosystem.Pip: source,
	}
	o := osv.New(vulnsDir, source.ID, dataSources,
		osv.WithTransformer(&transformer{}),
		osv.WithBucketResolver("pypi", resolvePyPI),
	)
	if err := o.Update(root); err != nil {
		return oops.In("echo-osv").Wrapf(err, "failed to update Echo OSV vulnerability data")
	}
	return nil
}

func resolvePyPI(_ string) (bucket.Bucket, error) {
	return newPipBucket(source)
}

// transformer filters out advisories that didn't resolve to a CVE ID.
// The Echo OSV feed contains both ECHO-ID and CVE-ID entries for the same
// vulnerability; keeping only CVE-keyed advisories avoids duplicates.
type transformer struct{}

func (t *transformer) PostParseAffected(adv osv.Advisory, _ osv.Affected) (osv.Advisory, error) {
	return adv, nil
}

func (t *transformer) TransformAdvisories(advisories []osv.Advisory, _ osv.Entry) ([]osv.Advisory, error) {
	var filtered []osv.Advisory
	for _, adv := range advisories {
		if strings.HasPrefix(adv.VulnerabilityID, "CVE-") {
			filtered = append(filtered, adv)
		}
	}
	return filtered, nil
}
