package chainguardosv

// Package mirrors one file written by the vuln-list-update "chainguard-osv"
// target: every advisory Chainguard has published for a single package within a
// single ecosystem.
type Package struct {
	Ecosystem  string     `json:"ecosystem"`
	Name       string     `json:"name"`
	Advisories []Advisory `json:"advisories"`
}

// Advisory is one Chainguard advisory as it applies to a single package and
// architecture. The v3 feed publishes one advisory per vulnerable component, so
// a package commonly has several advisories for the same vulnerability, which
// are aggregated when the advisories are stored.
type Advisory struct {
	// ID is the Chainguard advisory ID, e.g. CGA-2637-w437-j654.
	ID string `json:"id"`

	// Upstream lists the upstream vulnerability IDs, e.g. CVE-2023-38545.
	Upstream []string `json:"upstream"`

	// Arch is the CPU architecture of the package build, e.g. x86_64.
	// Empty when the advisory applies to every architecture.
	Arch string `json:"arch"`

	// Events holds the OSV ECOSYSTEM range events. An "introduced" event with
	// no "fixed" event means every version is affected and no fix exists yet.
	Events []Event `json:"events"`

	// Status is Chainguard's resolution status for the advisory, e.g. fixed,
	// pending_upstream_fix.
	Status string `json:"status"`
}

// Event is an OSV range event. Exactly one of the fields is set.
//
// OSV also defines "last_affected" and "limit" events, and the mirror carries
// them through if the feed ever emits one. They are not declared here because
// Trivy has no way to express them: an entry using them decodes as an event with
// no fixed version, which fixedVersion reports as unresolved.
type Event struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// fixedVersion returns the version the advisory was fixed in, and whether the
// advisory is resolved at all.
//
// The feed encodes three outcomes in the range events:
//   - "introduced" only: unresolved, every version is affected, no fix exists.
//   - "fixed" with a real version: fixed in that version.
//   - "fixed" with "0": a false positive determination, nothing is affected.
//
// Only the upper bound of the range is used. Trivy compares an installed version
// against a single fixed version and has no way to express a lower bound, so an
// advisory whose range starts partway through the version history is reported
// for versions below that start too. Every record in the feed carries
// "introduced": "0", and over-reporting the versions that predate a
// vulnerability is the safe direction if that ever changes.
//
// Several "fixed" events in one entry, which would mean disjoint affected
// ranges, cannot be reduced to one fixed version at all: taking the lowest
// would report the versions above it as safe. That shape is reported as
// unresolved instead, so it costs a false positive rather than a miss. The feed
// publishes exactly one range per affected entry, so this is a guard rather than
// a case that occurs.
func (a Advisory) fixedVersion() (version string, resolved bool) {
	var fixed []string
	for _, event := range a.Events {
		if event.Fixed != "" {
			fixed = append(fixed, event.Fixed)
		}
	}

	if len(fixed) != 1 {
		// No fixed event means Chainguard has not resolved the advisory; more
		// than one means a shape this cannot represent.
		return "", false
	}
	if fixed[0] == falsePositiveVersion {
		// "0" sorts below every real version, so it leaves an empty affected
		// range.
		return "", true
	}
	return fixed[0], true
}
