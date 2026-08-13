package rapidfort

// SourcePackageAdvisory is one per-package file from the RapidFort repo
// (OS/{osName}/{package_name}.json). One file bundles every distro version
// for a package; parse() fans it out per-version in-memory at DB-build time.
type SourcePackageAdvisory struct {
	PackageName string                         `json:"package_name"`
	Advisory    map[string]map[string]CVEEntry `json:"advisory"` // distroVersion -> cveID -> CVEEntry
}

// CVEEntry holds the advisory details for a single CVE within a distro release.
type CVEEntry struct {
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"` // "LOW", "MEDIUM", "HIGH", "CRITICAL"
	Events      []Event `json:"events"`
}

// Event is a version range: [Introduced, Fixed). An empty Fixed means the
// vulnerability is still open from Introduced onward.
type Event struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
	Identifier string `json:"identifier,omitempty"`
}
