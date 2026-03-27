package rapidfort

// PackageAdvisory matches the per-version per-package JSON format written by
// vuln-list-update's rapidfort package.
// File path: vuln-list/rapidfort/{os}/{version}/{package_name}.json
type PackageAdvisory struct {
	PackageName   string              `json:"package_name"`
	DistroVersion string              `json:"distro_version"`
	Advisories    map[string]CVEEntry `json:"advisories"` // cveID -> CVEEntry
}

// CVEEntry holds the advisory details for a single CVE within a distro release.
type CVEEntry struct {
	CVEID       string  `json:"cve_id"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"` // "LOW", "MEDIUM", "HIGH", "CRITICAL"
	Status      string  `json:"status"`   // "fixed" or "open"
	Events      []Event `json:"events"`
}

// Event represents a single version range — an introduced version and an optional fixed version.
// If Fixed is empty the vulnerability is still open for that introduced range.
type Event struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
	Identifier string `json:"identifier,omitempty"` // e.g. "el9", "fc39"; absent for ubuntu/alpine
}

// RapidFortCustom carries per-event metadata via types.Advisory.Custom.
// Identifiers is parallel to Advisory.VulnerableVersions — Identifiers[i]
// is the distro identifier (e.g. "el9") for VulnerableVersions[i].
// Only set when at least one event has a non-empty Identifier.
type RapidFortCustom struct {
	Identifiers []string `json:"identifiers,omitempty"`
}
