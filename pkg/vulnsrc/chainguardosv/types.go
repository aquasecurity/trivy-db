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
// Every record in the feed today is a single range starting at version "0", the
// only shape a single fixed version can express. Anything else - a range that
// starts partway through the version history, or several disjoint ranges - is
// reported as unresolved rather than approximated, so that a change in the feed
// costs a false positive rather than a missed vulnerability.
func (a Advisory) fixedVersion() (version string, resolved bool) {
	var fixed []string
	for _, event := range a.Events {
		if event.Introduced != "" && event.Introduced != introducedFromStart {
			return "", false
		}
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
