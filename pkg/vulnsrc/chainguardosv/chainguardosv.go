// Package chainguardosv stores the advisories published in Chainguard's OSV v3
// security feed. The feed replaces the deprecated secdb (security.json) feeds
// for both Chainguard Images and Wolfi, and unlike secdb it also publishes
// advisories that Chainguard has not resolved yet.
//
// Feed documentation:
// https://github.com/chainguard-dev/vulnerability-scanner-support/blob/main/docs/osv_v3_feed.md
package chainguardosv

import (
	"cmp"
	"encoding/json"
	"io"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	apkver "github.com/knqyf263/go-apk-version"
	"github.com/samber/lo"
	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
)

const (
	// feedDir is where vuln-list-update writes the grouped v3 advisories. It
	// sits beside vuln-list/chainguard rather than inside it, because the secdb
	// "chainguard" target removes that whole directory on every run.
	feedDir = "chainguard-osv/v3"

	// falsePositiveVersion is the fixed version Chainguard uses to record that
	// a vulnerability does not apply to a package after all.
	falsePositiveVersion = "0"

	// introducedFromStart is the "introduced" version every record in the feed
	// carries, meaning the vulnerability has been present since the first
	// version of the package.
	introducedFromStart = "0"
)

// Ecosystem describes one of the two ecosystems published in the feed.
type Ecosystem struct {
	// Name is the OSV ecosystem name, e.g. Chainguard.
	Name string

	// Dir is the directory under the feed directory holding this ecosystem's
	// package files, e.g. chainguard.
	Dir string

	// Bucket is the trivy-db bucket the advisories are stored in.
	Bucket bucket.Bucket

	// Source describes the origin of the advisories.
	Source types.DataSource
}

// statusRanks orders the unresolved advisory statuses from the one a user most
// needs to act on to the one they least need to act on. When several unresolved
// advisories cover the same package and vulnerability, the highest ranked
// status is the one reported.
//
// The statuses come from Chainguard's advisory model:
// https://edu.chainguard.dev/chainguard/chainguard-images/staying-secure/security-advisories/how-chainguard-issues/
var statusRanks = []struct {
	feedStatus string
	dbStatus   types.Status
}{
	// Chainguard has confirmed the vulnerability affects the package.
	{"true_positive_determination", types.StatusAffected},
	// A fix needs to come from the upstream project first.
	{"pending_upstream_fix", types.StatusFixDeferred},
	// Chainguard does not intend to fix the vulnerability.
	{"fix_not_planned", types.StatusWillNotFix},
	// Chainguard does not intend to investigate the vulnerability.
	{"analysis_not_planned", types.StatusWillNotFix},
	// The vulnerability was detected and is still being triaged.
	{"detection", types.StatusUnderInvestigation},
}

// VulnSrc stores the advisories for a single ecosystem of the v3 feed.
type VulnSrc struct {
	dbc        db.Operation
	ecosystem  Ecosystem
	bucketName string
}

// NewVulnSrc returns a VulnSrc for the given ecosystem.
func NewVulnSrc(ecosystem Ecosystem) VulnSrc {
	return VulnSrc{
		dbc:        db.Config{},
		ecosystem:  ecosystem,
		bucketName: ecosystem.Bucket.Name(),
	}
}

func (vs VulnSrc) Name() types.SourceID {
	return vs.ecosystem.Source.ID
}

// Update reads every package file for the ecosystem and stores the aggregated
// advisories.
func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", feedDir, vs.ecosystem.Dir)
	eb := oops.In(string(vs.ecosystem.Source.ID)).With("root_dir", rootDir)

	var packages []Package
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var pkg Package
		if err := json.NewDecoder(r).Decode(&pkg); err != nil {
			return eb.With("file_path", path).Wrapf(err, "json decode error")
		}
		// A package file from another ecosystem would silently pollute this
		// bucket, so ignore anything unexpected rather than trusting the path.
		if pkg.Ecosystem != vs.ecosystem.Name {
			return nil
		}
		packages = append(packages, pkg)
		return nil
	})
	if err != nil {
		return eb.Wrapf(err, "walk error")
	}

	if err := vs.save(packages); err != nil {
		return eb.Wrapf(err, "save error")
	}
	return nil
}

func (vs VulnSrc) save(packages []Package) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		if err := vs.dbc.PutDataSource(tx, vs.bucketName, vs.ecosystem.Source); err != nil {
			return oops.Wrapf(err, "failed to put data source")
		}
		for _, pkg := range packages {
			if err := vs.savePackage(tx, pkg); err != nil {
				return oops.With("package_name", pkg.Name).Wrapf(err, "failed to save package")
			}
		}
		return nil
	})
	if err != nil {
		return oops.Wrapf(err, "db batch update error")
	}
	return nil
}

func (vs VulnSrc) savePackage(tx *bolt.Tx, pkg Package) error {
	for vulnID, advisory := range Aggregate(pkg) {
		if err := vs.dbc.PutAdvisoryDetail(tx, vulnID, pkg.Name, []string{vs.bucketName}, advisory); err != nil {
			return oops.With("vuln_id", vulnID).Wrapf(err, "failed to save advisory")
		}

		// Optimization: store only vendor-detected vulnerabilities from NVD.
		if err := vs.dbc.PutVulnerabilityID(tx, vulnID); err != nil {
			return oops.With("vuln_id", vulnID).Wrapf(err, "failed to save the vulnerability ID")
		}
	}
	return nil
}

// Get returns the advisories stored for a package.
//
// Every architecture is returned, with the architectures each advisory applies
// to in Arches. Picking between them is left to the caller, because the feed
// does not always cover both architectures of a package and dropping an
// advisory whose architecture does not match would hide it entirely.
func (vs VulnSrc) Get(params db.GetParams) ([]types.Advisory, error) {
	eb := oops.In(string(vs.ecosystem.Source.ID)).With("package_name", params.PkgName)

	rawAdvisories, err := vs.dbc.ForEachAdvisory([]string{vs.bucketName}, params.PkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "advisory foreach error")
	}

	var advisories []types.Advisory
	for vulnID, v := range rawAdvisories {
		var stored types.Advisories
		if err := json.Unmarshal(v.Content, &stored); err != nil {
			return nil, eb.With("vuln_id", vulnID).Wrapf(err, "json unmarshal error")
		}

		var dataSource *types.DataSource
		if !lo.IsEmpty(v.Source) {
			dataSource = &types.DataSource{
				ID:     v.Source.ID,
				Name:   v.Source.Name,
				URL:    v.Source.URL,
				BaseID: v.Source.BaseID,
			}
		}

		// An advisory written before the v3 feed has no entries, only a fixed
		// version. A Trivy built against this package can be pointed at a
		// database built before it, and without this the advisory would be
		// dropped silently.
		if len(stored.Entries) == 0 {
			advisories = append(advisories, types.Advisory{
				VulnerabilityID: vulnID,
				FixedVersion:    stored.FixedVersion,
				DataSource:      dataSource,
				Custom:          stored.Custom,
			})
			continue
		}

		for _, entry := range stored.Entries {
			advisory := entry
			advisory.VulnerabilityID = vulnID
			advisory.DataSource = dataSource
			if advisory.Custom == nil {
				advisory.Custom = stored.Custom
			}
			advisories = append(advisories, advisory)
		}
	}
	return advisories, nil
}

// Aggregate reduces every advisory published for a package to one stored
// advisory per vulnerability ID.
//
// The v3 feed publishes one record per vulnerable component, so a package can
// carry many advisories for the same vulnerability and architecture. Chainguard
// defines how they combine: if any of them is unresolved the package is
// affected and no fix is offered, otherwise the package is fixed in the highest
// version any of them names, and if all of them are false positives the package
// is not affected at all.
func Aggregate(pkg Package) map[string]types.Advisories {
	// vulnerability ID -> architecture -> outcome
	outcomes := make(map[string]map[string]*outcome)
	for _, advisory := range pkg.Advisories {
		for _, vulnID := range advisory.Upstream {
			// Trivy tracks OS package vulnerabilities by CVE ID. The GHSA and
			// GO IDs the feed also lists are aliases of the same
			// vulnerability, and advisories with no CVE ID at all cannot be
			// reported against a CVE.
			if !strings.HasPrefix(vulnID, "CVE-") {
				continue
			}

			byArch, ok := outcomes[vulnID]
			if !ok {
				byArch = make(map[string]*outcome)
				outcomes[vulnID] = byArch
			}
			o, ok := byArch[advisory.Arch]
			if !ok {
				o = &outcome{}
				byArch[advisory.Arch] = o
			}
			o.add(advisory)
		}
	}

	advisories := make(map[string]types.Advisories, len(outcomes))
	for vulnID, byArch := range outcomes {
		if entries := entries(byArch); len(entries) > 0 {
			advisories[vulnID] = types.Advisories{
				// Kept so that a Trivy version that predates the v3 feed still
				// reads a fixed version out of this advisory.
				FixedVersion: highestFixedVersion(entries),
				Entries:      entries,
			}
		}
	}
	return advisories
}

// outcome accumulates the advisories that cover one package, architecture and
// vulnerability.
type outcome struct {
	// unresolvedRank is the index into statusRanks of the most pressing
	// unresolved status seen so far, or len(statusRanks) if none was seen.
	unresolvedRank int
	unresolvedID   string
	unresolved     bool

	fixedVersion string
	fixedID      string
}

func (o *outcome) add(advisory Advisory) {
	fixedVersion, resolved := advisory.fixedVersion()
	if !resolved {
		rank := statusRank(advisory.Status)
		if !o.unresolved || rank < o.unresolvedRank {
			o.unresolved = true
			o.unresolvedRank = rank
			o.unresolvedID = advisory.ID
		}
		return
	}
	if fixedVersion == "" {
		// A false positive determination: this component does not make the
		// package vulnerable.
		return
	}
	// The package is only free of the vulnerability once it reaches the highest
	// version any of its components was fixed in.
	if o.fixedVersion == "" || lessThan(o.fixedVersion, fixedVersion) {
		o.fixedVersion = fixedVersion
		o.fixedID = advisory.ID
	}
}

// advisory turns the accumulated outcome into a stored advisory, or reports
// false if the package is not affected.
func (o *outcome) advisory() (types.Advisory, bool) {
	switch {
	case o.unresolved:
		return types.Advisory{
			Status:    statusOf(o.unresolvedRank),
			VendorIDs: []string{o.unresolvedID},
		}, true
	case o.fixedVersion != "":
		return types.Advisory{
			FixedVersion: o.fixedVersion,
			VendorIDs:    []string{o.fixedID},
		}, true
	default:
		return types.Advisory{}, false
	}
}

// entries turns the per-architecture outcomes into stored entries, merging the
// architectures that ended up with the same outcome.
func entries(byArch map[string]*outcome) []types.Advisory {
	type merged struct {
		fixedVersion string
		status       types.Status
	}
	grouped := make(map[merged]*types.Advisory)
	for _, arch := range slices.Sorted(maps.Keys(byArch)) {
		advisory, affected := byArch[arch].advisory()
		if !affected {
			continue
		}

		key := merged{
			fixedVersion: advisory.FixedVersion,
			status:       advisory.Status,
		}
		existing, ok := grouped[key]
		if !ok {
			grouped[key] = &advisory
			existing = &advisory
		} else {
			existing.VendorIDs = appendUnique(existing.VendorIDs, advisory.VendorIDs...)
		}
		if arch != "" {
			existing.Arches = append(existing.Arches, arch)
		}
	}

	entries := make([]types.Advisory, 0, len(grouped))
	for _, advisory := range grouped {
		slices.Sort(advisory.VendorIDs)
		entries = append(entries, *advisory)
	}
	// Sort so that a rebuild of the database produces the same bytes.
	slices.SortFunc(entries, func(a, b types.Advisory) int {
		if c := cmp.Compare(a.FixedVersion, b.FixedVersion); c != 0 {
			return c
		}
		if c := cmp.Compare(int(a.Status), int(b.Status)); c != 0 {
			return c
		}
		return slices.Compare(a.Arches, b.Arches)
	})
	return entries
}

func highestFixedVersion(entries []types.Advisory) string {
	var highest string
	for _, entry := range entries {
		if entry.FixedVersion != "" && (highest == "" || lessThan(highest, entry.FixedVersion)) {
			highest = entry.FixedVersion
		}
	}
	return highest
}

// lessThan compares two APK versions. Versions that cannot be parsed fall back
// to a string comparison so that a malformed version in the feed still yields a
// deterministic result.
func lessThan(a, b string) bool {
	left, err := apkver.NewVersion(a)
	if err != nil {
		return a < b
	}
	right, err := apkver.NewVersion(b)
	if err != nil {
		return a < b
	}
	return left.LessThan(right)
}

func statusRank(feedStatus string) int {
	for i, s := range statusRanks {
		if s.feedStatus == feedStatus {
			return i
		}
	}
	// An unrecognized status still came with a range that says the package is
	// affected, so it is treated as such rather than being dropped.
	return len(statusRanks)
}

func statusOf(rank int) types.Status {
	if rank < 0 || rank >= len(statusRanks) {
		return types.StatusAffected
	}
	return statusRanks[rank].dbStatus
}

func appendUnique(dst []string, values ...string) []string {
	for _, value := range values {
		if !slices.Contains(dst, value) {
			dst = append(dst, value)
		}
	}
	return dst
}
