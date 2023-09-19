package k8svulndb

import (
	"path/filepath"

	"github.com/aquasecurity/trivy-db/pkg/types"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/osv"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/goark/go-cvss/v3/metric"
)

var (
	k8sDir = filepath.Join("vuln-list-k8s", "upstream")
)

func NewVulnSrc() osv.OSV {
	sources := map[types.Ecosystem]types.DataSource{
		vulnerability.K8s: {
			ID:   vulnerability.K8sVulnDB,
			Name: "Official Kubernetes CVE Feed",
			URL:  "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json",
		},
	}
	return osv.New(k8sDir, vulnerability.K8sVulnDB, sources, &transformer{})
}

type transformer struct{}

func (t *transformer) TransformAdvisories(advs []osv.Advisory, entry osv.Entry) ([]osv.Advisory, error) {
	if len(entry.Severities) == 0 {
		return advs, nil
	}
	severity := types.SeverityUnknown
	bm, err := metric.NewBase().Decode(entry.Severities[0].Type)
	if err == nil {
		severity = types.Severity(bm.Severity())
	}
	for i := range advs {
		advs[i].Severity = severity
	}
	return advs, nil
}
