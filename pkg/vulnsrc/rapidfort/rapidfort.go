package rapidfort

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const rapidfortDir = "rapidfort"

var source = types.DataSource{
	ID:   vulnerability.RapidFort,
	Name: "RapidFort Security Advisories",
	URL:  "https://github.com/rapidfort/security-advisories",
}

type config struct {
	dbc    db.Operation
	logger *log.Logger
}

// VulnSrc implements the vulnsrc.VulnSrc interface and is used to build the DB.
type VulnSrc struct {
	config
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		config: config{
			dbc:    db.Config{},
			logger: log.WithPrefix("rapidfort"),
		},
	}
}

func (vs VulnSrc) Name() types.SourceID {
	return source.ID
}

// Update reads all per-package JSON files from vuln-list/rapidfort/{os}/{version}/{pkg}.json
// and writes them into the BoltDB.
func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", rapidfortDir)
	eb := oops.In("rapidfort").With("root_dir", rootDir)

	entries, err := vs.parse(rootDir)
	if err != nil {
		return eb.Wrap(err)
	}
	if err = vs.put(entries); err != nil {
		return eb.Wrap(err)
	}
	return nil
}

type entry struct {
	platform string
	baseOS   string
	pkgName  string
	cveID    string
	advisory types.Advisory
	detail   types.VulnerabilityDetail
}

func (vs VulnSrc) parse(rootDir string) ([]entry, error) {
	eb := oops.In("rapidfort").With("root_dir", rootDir)
	var entries []entry

	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		if !strings.HasSuffix(path, ".json") {
			return nil
		}

		// Relative path: {osName}/{version}/{pkg}.json
		relPath, err := filepath.Rel(rootDir, path)
		if err != nil {
			return eb.With("path", path).Wrapf(err, "failed to make relative path")
		}
		parts := strings.SplitN(filepath.ToSlash(relPath), "/", 3)
		if len(parts) < 3 {
			vs.logger.Warn("Skipping file with unexpected path structure", "path", path)
			return nil
		}
		// Extract OS and version from the directory structure: {osName}/{version}/{pkg}.json
		// This is authoritative and avoids dependence on the JSON field name (distro_version vs distro_codename).
		osName := parts[0]
		version := parts[1]

		var pkg PackageAdvisory
		if err := json.NewDecoder(r).Decode(&pkg); err != nil {
			return eb.With("path", path).Wrapf(err, "json decode error")
		}

		b := bucket.NewRapidFort(osName, version)
		for cveID, cveEntry := range pkg.Advisories {
			entries = append(entries, entry{
				platform: b.Name(),
				baseOS:   b.BaseOS(),
				pkgName:  pkg.PackageName,
				cveID:    cveID,
				advisory: buildAdvisory(cveEntry),
				detail:   buildVulnerabilityDetail(cveEntry),
			})
		}
		return nil
	})
	if err != nil {
		return nil, oops.Wrapf(err, "walk error")
	}
	return entries, nil
}

func (vs VulnSrc) put(entries []entry) error {
	if len(entries) == 0 {
		vs.logger.Info("No RapidFort advisories found")
		return nil
	}
	vs.logger.Info("Saving RapidFort advisories", "count", len(entries))

	// Track unique platform → baseOS mappings for DataSource registration.
	platforms := map[string]string{}
	for _, e := range entries {
		platforms[e.platform] = e.baseOS
	}

	return vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		for platform, baseOS := range platforms {
			ds := types.DataSource{
				ID:     source.ID,
				Name:   source.Name,
				URL:    source.URL,
				BaseID: types.SourceID(baseOS),
			}
			if err := vs.dbc.PutDataSource(tx, platform, ds); err != nil {
				return oops.With("platform", platform).Wrapf(err, "failed to put data source")
			}
		}

		for _, e := range entries {
			eb := oops.With("platform", e.platform).With("package", e.pkgName).With("cve", e.cveID)

			if err := vs.dbc.PutAdvisoryDetail(tx, e.cveID, e.pkgName, []string{e.platform}, e.advisory); err != nil {
				return eb.Wrapf(err, "failed to save advisory")
			}
			if err := vs.dbc.PutVulnerabilityDetail(tx, e.cveID, source.ID, e.detail); err != nil {
				return eb.Wrapf(err, "failed to save vulnerability detail")
			}
			if err := vs.dbc.PutVulnerabilityID(tx, e.cveID); err != nil {
				return eb.Wrapf(err, "failed to save vulnerability ID")
			}
		}
		return nil
	})
}

// buildAdvisory converts a CVEEntry's Events into the trivy-db Advisory format.
// Each event represents a version range: Introduced..Fixed (or open-ended if Fixed is empty).
func buildAdvisory(cve CVEEntry) types.Advisory {
	var patched, vulnerable, identifiers []string
	var hasIdentifier bool
	for _, ev := range cve.Events {
		switch {
		case ev.Fixed != "":
			patched = append(patched, ev.Fixed)
			if ev.Introduced != "" {
				// Comma-separated: each part is parsed individually by newConstraint which handles spaces.
				vulnerable = append(vulnerable, fmt.Sprintf(">= %s, < %s", ev.Introduced, ev.Fixed))
			} else {
				// Single constraint: write without space so the existing space-based splitter
				// doesn't break it into ["<", "version"].
				vulnerable = append(vulnerable, fmt.Sprintf("<%s", ev.Fixed))
			}
		case ev.Introduced != "":
			// Open vulnerability (no fix): write without space for the same reason.
			vulnerable = append(vulnerable, fmt.Sprintf(">=%s", ev.Introduced))
		default:
			continue
		}
		// Track identifiers parallel to vulnerable versions.
		identifiers = append(identifiers, ev.Identifier)
		if ev.Identifier != "" {
			hasIdentifier = true
		}
	}

	severity := types.SeverityUnknown
	if sev, err := types.NewSeverity(strings.ToUpper(cve.Severity)); err == nil {
		severity = sev
	}

	adv := types.Advisory{
		PatchedVersions:    patched,
		VulnerableVersions: vulnerable,
		Severity:           severity,
	}

	// Only set Custom when at least one event carries an identifier (e.g. redhat).
	// Ubuntu/alpine events have no identifiers, so Custom stays nil for them.
	if hasIdentifier {
		adv.Custom = RapidFortCustom{
			Identifiers: identifiers,
		}
	}

	return adv
}

// buildVulnerabilityDetail constructs a VulnerabilityDetail from a CVEEntry for
// enriching the vulnerability bucket with title, description and severity.
func buildVulnerabilityDetail(cve CVEEntry) types.VulnerabilityDetail {
	severity := types.SeverityUnknown
	if sev, err := types.NewSeverity(strings.ToUpper(cve.Severity)); err == nil {
		severity = sev
	}
	return types.VulnerabilityDetail{
		Title:       cve.Title,
		Description: cve.Description,
		Severity:    severity,
	}
}

// VulnSrcGetter is used by trivy (the scanner) to query advisories from the DB
// for a specific base OS (e.g. "ubuntu" or "debian").
type VulnSrcGetter struct {
	baseOS string
	config
}

func NewVulnSrcGetter(baseOS string) VulnSrcGetter {
	return VulnSrcGetter{
		baseOS: baseOS,
		config: config{
			dbc:    db.Config{},
			logger: log.WithPrefix("rapidfort-" + baseOS),
		},
	}
}

// Get returns RapidFort advisories for a given package and OS version (e.g. "22.04").
func (vs VulnSrcGetter) Get(params db.GetParams) ([]types.Advisory, error) {
	eb := oops.In("rapidfort").With("base_os", vs.baseOS).With("os_version", params.Release).With("package_name", params.PkgName)

	platformName := bucket.NewRapidFort(vs.baseOS, params.Release).Name()
	advs, err := vs.dbc.GetAdvisories(platformName, params.PkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get advisories")
	}
	return advs, nil
}
