package ghsa

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/packages"
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
	standardGoPackages = make(map[string]struct{})
)

func init() {
	pkgs, err := packages.Load(nil, "std")
	if err != nil {
		panic(err)
	}

	for _, p := range pkgs {
		standardGoPackages[p.PkgPath] = struct{}{}
	}
}

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

	severity := convertSeverity(specific.Severity)
	for i, adv := range advisories {
		// Parse database_specific
		if err := parseDatabaseSpecific(adv); err != nil {
			return nil, xerrors.Errorf("failed to parse database specific: %w", err)
		}

		// Fill severity from GHSA
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

		// Skip a standard Go package as we use the Go Vulnerability Database (govulndb) for standard packages.
		if adv.Ecosystem == vulnerability.Go {
			if isStandardGoPackage(adv.PkgName) {
				advisories[i].Ecosystem = "" // An empty ecosystem is skipped later
			}
		}
	}

	return advisories, nil
}

// parseDatabaseSpecific adds a version from the last_known_affected_version_range field
// cf. https://github.com/github/advisory-database/issues/470#issuecomment-1998604377
func parseDatabaseSpecific(advisory osv.Advisory) error {
	// Skip if the `affected[].database_specific` field doesn't exist
	if advisory.DatabaseSpecific == nil {
		return nil
	}

	var affectedSpecific DatabaseSpecific
	if err := json.Unmarshal(advisory.DatabaseSpecific, &affectedSpecific); err != nil {
		return xerrors.Errorf("JSON decode error: %w", err)
	}

	for i, vulnVersion := range advisory.VulnerableVersions {
		// The fixed and last_affected fields (which use <, <=, or =) take precedence over
		// the last_known_affected_version_range field.
		if strings.Contains(vulnVersion, "<") || strings.HasPrefix(vulnVersion, "=") {
			continue
		}
		// `last_known_affected_version_range` uses `< version` or `<= version` formats (e.g. `< 1.2.3` or `<= 1.2.3`).
		// Remove spaces to match our format
		verRange := strings.ReplaceAll(affectedSpecific.LastKnownAffectedVersionRange, " ", "")
		advisory.VulnerableVersions[i] = fmt.Sprintf("%s, %s", vulnVersion, verRange)
	}
	return nil
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

func isStandardGoPackage(pkg string) bool {
	_, ok := standardGoPackages[pkg]
	return ok
}
