package bitnami

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/osv"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

var bitnamiDir = filepath.Join("bitnami-vulndb", "data")

func NewVulnSrc() osv.OSV {
	sources := map[types.Ecosystem]types.DataSource{
		vulnerability.Bitnami: {
			ID:   vulnerability.BitnamiVulndb,
			Name: "Bitnami Vulnerability Database",
			URL:  "https://github.com/bitnami/vulndb",
		},
	}

	return osv.New(bitnamiDir, vulnerability.BitnamiVulndb, sources, &transformer{})
}

type transformer struct{}

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
