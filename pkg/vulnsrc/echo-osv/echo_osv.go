package echoosv

import (
	"path/filepath"
	"strings"

	"github.com/samber/lo"
	"github.com/samber/oops"

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
		URL:  "https://advisory.echohq.com/osv/all.zip",
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
	o := osv.New(vulnsDir, source.ID, nil,
		osv.WithTransformer(&transformer{}),
		osv.WithBucketResolver("echo", resolveEcho),
	)
	if err := o.Update(root); err != nil {
		return oops.In("echo-osv").Wrapf(err, "failed to update Echo OSV vulnerability data")
	}
	return nil
}

// resolveEcho maps an Echo OSV ecosystem to a bucket.
// resolveBucket lowercases the ecosystem and splits it on ':', so "Echo:PyPI"
// arrives here as suffix "pypi" and plain "Echo" (OS packages) as "".
func resolveEcho(suffix string) (bucket.Bucket, error) {
	switch suffix {
	case "pypi":
		return newPipBucket(source)
	default:
		// Only PyPI is supported for now. Plain "Echo" (OS packages, served by
		// the `echo` source) and other suffixes are skipped by the OSV parser.
		return nil, oops.Errorf("unsupported Echo ecosystem suffix: %q", suffix)
	}
}

// transformer re-keys advisories that didn't resolve to a CVE ID.
// Every Echo OSV entry is keyed by an opaque ECHO ID and records the
// authoritative IDs in `upstream`. The OSV parser promotes an upstream CVE to
// the vulnerability ID, but when there is no CVE the advisory keeps its ECHO
// ID, which nothing matches on. Fall back to the upstream GHSA in that case,
// and drop entries that have neither.
type transformer struct{}

func (t *transformer) PostParseAffected(adv osv.Advisory, _ osv.Affected) (osv.Advisory, error) {
	return adv, nil
}

func (t *transformer) TransformAdvisories(advisories []osv.Advisory, entry osv.Entry) ([]osv.Advisory, error) {
	ghsaID, hasGHSA := lo.Find(entry.Upstream, func(id string) bool {
		return strings.HasPrefix(id, "GHSA-")
	})

	var filtered []osv.Advisory
	for _, adv := range advisories {
		if !strings.HasPrefix(adv.VulnerabilityID, "CVE-") {
			if !hasGHSA {
				continue
			}
			// Key the advisory by the GHSA and keep the ECHO ID as a vendor ID.
			adv.VulnerabilityID = ghsaID
			adv.Aliases = lo.Uniq(append(lo.Without(adv.Aliases, ghsaID), entry.ID))
		}
		filtered = append(filtered, adv)
	}
	return filtered, nil
}
