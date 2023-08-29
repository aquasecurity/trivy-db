package bitnami

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/osv"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"golang.org/x/xerrors"
)

var bitnamiDir = filepath.Join("bitnami-vulndb", "data")

type BitnamiVulnSrc struct{}

func NewVulnSrc() BitnamiVulnSrc {
	return BitnamiVulnSrc{}
}

func (BitnamiVulnSrc) Name() types.SourceID {
	return vulnerability.BitnamiVulndb
}

func (b BitnamiVulnSrc) Update(root string) error {
	sources := map[types.Ecosystem]types.DataSource{
		vulnerability.Bitnami: {
			ID:   b.Name(),
			Name: "Bitnami Vulnerability Database",
			URL:  "https://github.com/bitnami/vulndb",
		},
	}

	return osv.New(bitnamiDir, b.Name(), sources, newTransformer()).Update(root)
}

type transformer struct{}

func newTransformer() *transformer {
	return &transformer{}
}

type DatabaseSpecific struct {
	Severity string `json:"severity"`
}

func (t *transformer) TransformAdvisories(advs []osv.Advisory, entry osv.Entry) ([]osv.Advisory, error) {
	var specific DatabaseSpecific
	if err := json.Unmarshal(entry.DatabaseSpecific, &specific); err != nil {
		return nil, xerrors.Errorf("JSON decode error: %w", err)
	}

	severity := convertSeverity(specific.Severity)
	for i := range advs {
		advs[i].Severity = severity
	}

	return advs, nil
}

func convertSeverity(severity string) types.Severity {
	switch strings.ToLower(severity) {
	case "low":
		return types.SeverityLow
	case "moderate":
		return types.SeverityMedium
	case "high":
		return types.SeverityHigh
	case "critical":
		return types.SeverityCritical
	default:
		return types.SeverityUnknown
	}
}
