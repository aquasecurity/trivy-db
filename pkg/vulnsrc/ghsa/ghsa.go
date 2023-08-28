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

type GHSA struct{}

func NewVulnSrc() GHSA {
	return GHSA{}
}

func (GHSA) Name() types.SourceID {
	return vulnerability.GHSA
}

func (GHSA) Update(root string) error {
	dataSources := map[types.Ecosystem]types.DataSource{}
	for _, ecosystem := range ecosystems {
		src := types.DataSource{
			ID:   sourceID,
			Name: fmt.Sprintf(platformFormat, cases.Title(language.English).String(string(ecosystem))),
			URL:  fmt.Sprintf("https://github.com/advisories?query=type%%3Areviewed+ecosystem%%3A%s", ecosystem),
		}
		dataSources[ecosystem] = src

		// CocoaPods' vulnerability detection uses the Swift advisories.
		if ecosystem == vulnerability.Swift {
			dataSources[vulnerability.Cocoapods] = src
		}
	}

	t, err := newTransformer(root)
	if err != nil {
		return xerrors.Errorf("transformer error: %w", err)
	}

	return osv.New(ghsaDir, sourceID, dataSources, t).Update(root)
}

type transformer struct {
	// cocoaPodsSpecs is a map of Swift git URLs to CocoaPods package names.
	cocoaPodsSpecs map[string][]string
}

func newTransformer(root string) (*transformer, error) {
	cocoaPodsSpecs, err := walkCocoaPodsSpecs(root)
	if err != nil {
		return nil, xerrors.Errorf("CocoaPods spec error: %w", err)
	}
	return &transformer{
		cocoaPodsSpecs: cocoaPodsSpecs,
	}, nil
}

func (t *transformer) TransformAdvisories(advisories []osv.Advisory, entry osv.Entry) ([]osv.Advisory, error) {
	var specific DatabaseSpecific
	if err := json.Unmarshal(entry.DatabaseSpecific, &specific); err != nil {
		return nil, xerrors.Errorf("JSON decode error: %w", err)
	}

	severity := convertSeverity(specific.Severity)
	for i, adv := range advisories {
		advisories[i].Severity = severity

		// Replace a git URL with a CocoaPods package name in a Swift vulnerability
		// and store it as a CocoaPods vulnerability.
		if adv.Ecosystem == vulnerability.Swift {
			adv.Severity = severity
			adv.Ecosystem = vulnerability.Cocoapods
			for _, pkgName := range t.cocoaPodsSpecs[adv.PkgName] {
				adv.PkgName = pkgName
				advisories = append(advisories, adv)
			}
		}
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
