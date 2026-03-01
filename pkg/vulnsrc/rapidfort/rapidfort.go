package rapidfort

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	rapidfortDir   = "rapidfort"
	platformFormat = "rapidfort %s %s" // "rapidfort ubuntu 22.04"
)

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

	// Collect advisories grouped by platform name before batching the DB write.
	type entry struct {
		platform string
		pkgName  string
		cveID    string
		advisory types.Advisory
		detail   types.VulnerabilityDetail
	}
	var entries []entry

	err := filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
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

		data, err := os.ReadFile(path)
		if err != nil {
			return eb.With("path", path).Wrapf(err, "failed to read file")
		}

		var pkg PackageAdvisory
		if err := json.Unmarshal(data, &pkg); err != nil {
			return eb.With("path", path).Wrapf(err, "json decode error")
		}

		platformName := fmt.Sprintf(platformFormat, osName, version)

		for cveID, cveEntry := range pkg.Advisories {
			advisory := buildAdvisory(cveEntry)
			detail := buildVulnerabilityDetail(cveEntry)
			entries = append(entries, entry{
				platform: platformName,
				pkgName:  pkg.PackageName,
				cveID:    cveID,
				advisory: advisory,
				detail:   detail,
			})
		}
		return nil
	})
	if err != nil {
		return eb.Wrapf(err, "directory walk error")
	}

	if len(entries) == 0 {
		vs.logger.Info("No RapidFort advisories found", "root_dir", rootDir)
		return nil
	}

	vs.logger.Info("Saving RapidFort advisories", "count", len(entries))

	// Group entries by platform for efficient DataSource writes.
	platforms := map[string]struct{}{}
	for _, e := range entries {
		platforms[e.platform] = struct{}{}
	}

	return vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		// Register the data source once per platform bucket.
		for platform := range platforms {
			// Extract the base OS from the platform name ("rapidfort ubuntu 22.04" → "ubuntu").
			baseParts := strings.SplitN(platform, " ", 3)
			baseOS := ""
			if len(baseParts) >= 2 {
				baseOS = baseParts[1]
			}
			ds := types.DataSource{
				ID:     source.ID,
				Name:   source.Name,
				URL:    source.URL,
				BaseID: types.SourceID(baseOS),
			}
			if err := vs.dbc.PutDataSource(tx, platform, ds); err != nil {
				return oops.Wrapf(err, "failed to put data source for platform %s", platform)
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
	var patched, vulnerable []string
	for _, ev := range cve.Events {
		if ev.Fixed != "" {
			patched = append(patched, ev.Fixed)
			if ev.Introduced != "" {
				// Comma-separated: each part is parsed individually by newConstraint which handles spaces.
				vulnerable = append(vulnerable, fmt.Sprintf(">= %s, < %s", ev.Introduced, ev.Fixed))
			} else {
				// Single constraint: write without space so the existing space-based splitter
				// doesn't break it into ["<", "version"].
				vulnerable = append(vulnerable, fmt.Sprintf("<%s", ev.Fixed))
			}
		} else if ev.Introduced != "" {
			// Open vulnerability (no fix): write without space for the same reason.
			vulnerable = append(vulnerable, fmt.Sprintf(">=%s", ev.Introduced))
		}
	}

	severity := types.SeverityUnknown
	if sev, err := types.NewSeverity(strings.ToUpper(cve.Severity)); err == nil {
		severity = sev
	}

	return types.Advisory{
		PatchedVersions:    patched,
		VulnerableVersions: vulnerable,
		Severity:           severity,
	}
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
			logger: log.WithPrefix(fmt.Sprintf("rapidfort-%s", baseOS)),
		},
	}
}

// Get returns RapidFort advisories for a given package and OS version (e.g. "22.04").
func (vs VulnSrcGetter) Get(params db.GetParams) ([]types.Advisory, error) {
	eb := oops.In("rapidfort").With("base_os", vs.baseOS).With("os_version", params.Release).With("package_name", params.PkgName)

	platformName := fmt.Sprintf(platformFormat, vs.baseOS, params.Release)
	advs, err := vs.dbc.GetAdvisories(platformName, params.PkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get advisories")
	}
	return advs, nil
}
