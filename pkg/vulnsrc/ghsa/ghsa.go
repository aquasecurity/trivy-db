package ghsa

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/samber/lo"
	"github.com/samber/oops"
	"golang.org/x/tools/go/packages"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
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
	ecosystems = map[ecosystem.Type]string{
		ecosystem.Composer:  "Composer",
		ecosystem.Go:        "Go",
		ecosystem.Maven:     "Maven",
		ecosystem.Npm:       "npm",
		ecosystem.NuGet:     "NuGet",
		ecosystem.Pip:       "pip",
		ecosystem.RubyGems:  "RubyGems",
		ecosystem.Cargo:     "Rust", // different name
		ecosystem.Erlang:    "Erlang",
		ecosystem.Pub:       "Pub",
		ecosystem.Swift:     "Swift",
		ecosystem.Cocoapods: "Swift", // Use Swift advisories for CocoaPods
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
	eb := oops.In("ghsa").With("root_dir", root)
	dataSources := map[ecosystem.Type]types.DataSource{}
	for eco, ghsaEcosystem := range ecosystems {
		src := types.DataSource{
			ID:   sourceID,
			Name: fmt.Sprintf(platformFormat, ghsaEcosystem),
			URL:  fmt.Sprintf(urlFormat, strings.ToLower(ghsaEcosystem)),
		}
		dataSources[eco] = src
	}

	t, err := newTransformer(root)
	if err != nil {
		return eb.Wrapf(err, "transformer error")
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
		return nil, oops.Wrapf(err, "CocoaPods spec error")
	}
	return &transformer{
		cocoaPodsSpecs: cocoaPodsSpecs,
	}, nil
}

func (t *transformer) PostParseAffected(adv osv.Advisory, affected osv.Affected) (osv.Advisory, error) {
	eb := oops.With("ecosystem", adv.Bucket.Ecosystem()).With("package_name", adv.PkgName).With("vuln_id", adv.VulnerabilityID).With("aliases", adv.Aliases)
	if err := parseDatabaseSpecific(adv, affected.DatabaseSpecific); err != nil {
		return osv.Advisory{}, eb.Wrapf(err, "failed to parse database specific")
	}
	return adv, nil
}

func (t *transformer) TransformAdvisories(advisories []osv.Advisory, entry osv.Entry) ([]osv.Advisory, error) {
	var specific DatabaseSpecific
	if err := json.Unmarshal(entry.DatabaseSpecific, &specific); err != nil {
		return nil, oops.Wrapf(err, "json unmarshal error")
	}

	originPkgNames := lo.SliceToMap(entry.Affected, func(affected osv.Affected) (string, string) {
		return strings.ToLower(affected.Package.Name), affected.Package.Name
	})

	severity := convertSeverity(specific.Severity)
	for i, adv := range advisories {
		// Fill severity from GHSA
		advisories[i].Severity = severity

		switch adv.Bucket.Ecosystem() {
		case ecosystem.Swift:
			// Replace a git URL with a CocoaPods package name in a Swift vulnerability
			// and store it as a CocoaPods vulnerability.
			adv.Severity = severity
			dsb, ok := adv.Bucket.(bucket.DataSourceBucket)
			if !ok {
				return nil, oops.With("package_name", adv.PkgName).With("bucket_type", fmt.Sprintf("%T", adv.Bucket)).
					With("source_ecosystem", ecosystem.Swift).Errorf("Swift bucket does not implement DataSourceBucket interface")
			}
			var err error
			if adv.Bucket, err = bucket.NewCocoapods(dsb.DataSource()); err != nil {
				return nil, oops.With("package_name", adv.PkgName).With("source_ecosystem", ecosystem.Swift).
					With("target_ecosystem", ecosystem.Cocoapods).Wrapf(err, "failed to create Cocoapods bucket")
			}

			for _, pkgName := range t.cocoaPodsSpecs[adv.PkgName] {
				adv.PkgName = pkgName
				advisories = append(advisories, adv)
			}
		case ecosystem.Go:
			// Skip a standard Go package as we use the Go Vulnerability Database (govulndb) for standard packages.
			if isStandardGoPackage(adv.PkgName) {
				advisories[i].Bucket = nil // Set nil bucket to skip later
			}
		case ecosystem.NuGet:
			// NuGet is case-insensitive, so we store advisories in lowercase.
			// However, for backward compatibility, we also keep advisories with the original package name.
			// TODO: drop storing the original-case entry and keep only the lowercase key once downstream users have migrated.
			if originPkgName, ok := originPkgNames[adv.PkgName]; ok && originPkgName != adv.PkgName {
				dup := advisories[i]
				dup.PkgName = originPkgName
				advisories = append(advisories, dup)
			}
		}
	}

	return advisories, nil
}

// parseDatabaseSpecific adds a version from the last_known_affected_version_range field
// cf. https://github.com/github/advisory-database/issues/470#issuecomment-1998604377
func parseDatabaseSpecific(advisory osv.Advisory, databaseSpecific json.RawMessage) error {
	// Skip if the `affected[].database_specific` field doesn't exist
	if databaseSpecific == nil {
		return nil
	}

	var affectedSpecific DatabaseSpecific
	if err := json.Unmarshal(databaseSpecific, &affectedSpecific); err != nil {
		return oops.Wrapf(err, "json unmarshal error")
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
