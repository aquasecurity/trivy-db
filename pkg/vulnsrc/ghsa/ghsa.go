package ghsa

import (
	"encoding/json"
	"fmt"
	"github.com/samber/lo"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/osv"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	sourceID       = vulnerability.GHSA
	platformFormat = "GitHub Security Advisory %s"
	urlFormat      = "https://github.com/advisories?query=type%%3Areviewed+ecosystem%%3A%s"
)

var (
	ghsaDir = filepath.Join("ghsa", "advisories", "github-reviewed")

	// Mapping between Trivy ecosystem and GHSA ecosystem
	ecosystems = map[types.Ecosystem]string{
		vulnerability.Composer:  "Composer",
		vulnerability.Go:        "Go",
		vulnerability.Maven:     "Maven",
		vulnerability.Npm:       "npm",
		vulnerability.NuGet:     "NuGet",
		vulnerability.Pip:       "pip",
		vulnerability.RubyGems:  "RubyGems",
		vulnerability.Cargo:     "Rust", // different name
		vulnerability.Erlang:    "Erlang",
		vulnerability.Pub:       "Pub",
		vulnerability.Swift:     "Swift",
		vulnerability.Cocoapods: "Swift", // Use Swift advisories for CocoaPods
	}
)

type DatabaseSpecific struct {
	Severity                      string `json:"severity"`
	LastKnownAffectedVersionRange string `json:"last_known_affected_version_range"`
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
	for ecosystem, ghsaEcosystem := range ecosystems {
		src := types.DataSource{
			ID:   sourceID,
			Name: fmt.Sprintf(platformFormat, ghsaEcosystem),
			URL:  fmt.Sprintf(urlFormat, strings.ToLower(ghsaEcosystem)),
		}
		dataSources[ecosystem] = src
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

	for _, affected := range entry.Affected {
		// Skip if `affected[].database_specific` field doesn't exist
		if affected.DatabaseSpecific == nil {
			continue
		}

		ecosystem := osv.ConvertEcosystem(affected.Package.Ecosystem)
		if ecosystem == vulnerability.Unknown {
			continue
		}
		pkgName := vulnerability.NormalizePkgName(ecosystem, affected.Package.Name)

		var affectedSpecific DatabaseSpecific
		if err := json.Unmarshal(affected.DatabaseSpecific, &affectedSpecific); err != nil {
			return nil, xerrors.Errorf("JSON decode error: %w", err)
		}

		// Add version from `last_known_affected_version_range` field
		// cf. https://github.com/github/advisory-database/issues/470#issuecomment-1998604377
		advisories = lo.Map(advisories, func(adv osv.Advisory, _ int) osv.Advisory {
			if adv.PkgName == pkgName && adv.Ecosystem == ecosystem {
				for i, vulnVersion := range adv.VulnerableVersions {
					// Skip next cases:
					// - vulnerability version range is single version (`=` is used)
					// - vulnerability version range already contains fixed/affected version (`<`/`<=` is used)
					if !strings.Contains(vulnVersion, "<") && !strings.HasPrefix(vulnVersion, "=") {
						// `last_known_affected_version_range` uses `< version` or `<= version` formats (e.g. `< 1.2.3` or `<= 1.2.3`).
						// Remove space to fit our format.
						affectedSpecific.LastKnownAffectedVersionRange = strings.ReplaceAll(affectedSpecific.LastKnownAffectedVersionRange, " ", "")
						adv.VulnerableVersions[i] = fmt.Sprintf("%s, %s", vulnVersion, affectedSpecific.LastKnownAffectedVersionRange)
						break
					}
				}
			}
			return adv
		})
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
