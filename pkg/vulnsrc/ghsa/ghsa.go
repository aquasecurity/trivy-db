package ghsa

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/osv"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	sourceID       = vulnerability.GHSA
	platformFormat = "GitHub Security Advisory %s"
)

var (
	ghsaDir    = filepath.Join("ghsa", "advisories", "github-reviewed")
	ecosystems = []types.Ecosystem{
		vulnerability.Composer,
		vulnerability.Go,
		vulnerability.Maven,
		vulnerability.Npm,
		vulnerability.NuGet,
		vulnerability.Pip,
		vulnerability.RubyGems,
		vulnerability.Rust,
		vulnerability.Erlang,
		vulnerability.Pub,
		vulnerability.Swift,
	}
)

type DatabaseSpecific struct {
	Severity string `json:"severity"`
}

func NewVulnSrc() osv.OSV {
	dataSources := map[types.Ecosystem]types.DataSource{}
	for _, ecosystem := range ecosystems {
		dataSources[ecosystem] = types.DataSource{
			ID:   sourceID,
			Name: fmt.Sprintf(platformFormat, cases.Title(language.English).String(string(ecosystem))),
			URL:  fmt.Sprintf("https://github.com/advisories?query=type%%3Areviewed+ecosystem%%3A%s", ecosystem),
		}
	}
	return osv.New(ghsaDir, sourceID, dataSources, &transformer{})
}

type transformer struct{}

func (*transformer) TransformAdvisories(advisories []osv.Advisory, entry osv.Entry) ([]osv.Advisory, error) {
	var specific DatabaseSpecific
	if err := json.Unmarshal(entry.DatabaseSpecific, &specific); err != nil {
		return nil, xerrors.Errorf("JSON decode error: %w", err)
	}

	severity := convertSeverity(specific.Severity)
	for i := range advisories {
		advisories[i].Severity = severity
	}
	return advisories, nil
}

func convertSeverity(severity string) types.Severity {
	switch severity {
	case "LOW":
		return types.SeverityLow
	case "MODERATE":
		return types.SeverityMedium
	case "HIGH":
		return types.SeverityHigh
	case "CRITICAL":
		return types.SeverityCritical
	default:
		return types.SeverityUnknown
	}
}
