package rapidfort

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const rapidfortDir = "rapidfort-security-advisories"

// osSubDir is the top-level directory inside the RapidFort security-advisories
// repo that groups advisory JSON files by operating system.
const osSubDir = "OS"

// Supported `Event.Identifier` values. A feed's own distribution is named by
// its ecosystem string ("ubuntu", "debian"), so it needs no constant here.
const (
	rapidFortIdentifier = "rf"
	redHatIdentifier    = "el"
	amazonIdentifier    = "amzn"
	fedoraIdentifier    = "fc"
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

// Update reads all per-package JSON files from {dir}/rapidfort-security-advisories/OS/{os}/
// and writes them into the BoltDB.
func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, rapidfortDir, osSubDir)
	eb := oops.In("rapidfort").With("root_dir", rootDir)

	entries, err := vs.parse(rootDir)
	if err != nil {
		return eb.Wrap(err)
	}
	if err = vs.put(mergeEntries(entries)); err != nil {
		return eb.Wrap(err)
	}
	return nil
}

// mergeEntries folds entries targeting the same (platform, package, CVE) into
// one. split already collapses the ranges within a single file, but two files
// can still describe the same artifact: every RPM feed carries fcNN ranges, and
// those all resolve to the shared "rapidfort fedora NN" buckets. put writes one
// entry after another, so without this only whichever file the walk visited last
// would survive. Feeds with no such overlap pass through unchanged.
func mergeEntries(entries []entry) []entry {
	type key struct{ platform, pkgName, cveID string }

	// Preserve first-seen order so the resulting DB does not depend on Go's map iteration order.
	index := make(map[key]int, len(entries))
	merged := make([]entry, 0, len(entries))
	for _, e := range entries {
		// Name() concatenates the platform string, so compute it once per entry.
		k := key{e.bucket.Name(), e.pkgName, e.cveID}
		i, seen := index[k]
		if !seen {
			index[k] = len(merged)
			merged = append(merged, e)
			continue
		}
		merged[i].advisory = mergeAdvisory(merged[i].advisory, e.advisory)
	}
	return merged
}

// mergeAdvisory unions two advisories for the same platform, package and CVE
// onto the first-seen one. The two version lists are independent (no per-range
// identifier is stored), so each is unioned on its own. Severity takes the
// higher of the two: the constants are ordered, so a feed that left it Unknown
// never overrides one that rated it.
func mergeAdvisory(a, b types.Advisory) types.Advisory {
	a.PatchedVersions = unionSorted(a.PatchedVersions, b.PatchedVersions)
	a.VulnerableVersions = unionSorted(a.VulnerableVersions, b.VulnerableVersions)
	a.Severity = max(a.Severity, b.Severity)
	return a
}

// unionSorted concatenates two version lists, then sorts and de-duplicates
// them. It returns nil rather than an empty slice so a merged Advisory stays
// identical to an unmerged one when both inputs are empty.
func unionSorted(a, b []string) []string {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	out := make([]string, 0, len(a)+len(b))
	out = append(out, a...)
	out = append(out, b...)
	// Compact only removes adjacent duplicates, hence the sort first — which
	// buildAdvisory already relies on for a stable on-disk DB.
	slices.Sort(out)
	return slices.Compact(out)
}

type entry struct {
	bucket   bucket.DataSourceBucket
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

		// Relative path: {osName}/{pkg}.json; the distro version lives inside the JSON.
		relPath, err := filepath.Rel(rootDir, path)
		if err != nil {
			return eb.With("path", path).Wrapf(err, "failed to make relative path")
		}
		parts := strings.SplitN(filepath.ToSlash(relPath), "/", 2)
		if len(parts) < 2 {
			vs.logger.Warn("Skipping file with unexpected path structure", "path", path)
			return nil
		}
		eco := ecosystem.Type(parts[0])

		// RapidFort owns which OSes its feed ships, so an OS this build doesn't ingest (e.g. debian) is expected rather than something to warn about on every file.
		if _, err := newBucket(eco, ""); err != nil {
			return nil
		}

		var src SourcePackageAdvisory
		if err := json.NewDecoder(r).Decode(&src); err != nil {
			return eb.With("path", path).Wrapf(err, "json decode error")
		}

		// One file can carry ranges for several distributions, tagged per range
		// by an identifier, so route each range to the bucket it belongs to
		// before converting.
		entries = append(entries, toEntries(src.PackageName, vs.split(eco, src, path))...)
		return nil
	})
	if err != nil {
		return nil, oops.Wrapf(err, "walk error")
	}
	return entries, nil
}

// toEntries converts the per-bucket advisories of one package into DB entries.
func toEntries(pkgName string, buckets map[bucket.DataSourceBucket]map[string]CVEEntry) []entry {
	var entries []entry
	for b, cveMap := range buckets {
		for cveID, cve := range cveMap {
			entries = append(entries, entry{
				bucket:   b,
				pkgName:  pkgName,
				cveID:    cveID,
				advisory: buildAdvisory(cve),
				detail:   buildVulnerabilityDetail(cve),
			})
		}
	}
	return entries
}

// split re-keys one feed file into an advisory set per bucket its ranges target.
// One file can mix distributions, so it is the identifier of a range, not the version key it sits under, that decides the bucket:
//
//	OS/redhat/rf-curl.json, key "9":     el9 → rapidfort Red Hat 9, fc42 → rapidfort fedora 42, rf → rapidfort Red Hat
//	OS/ubuntu/rf-curl.json, key "22.04": ubuntu or untagged → rapidfort ubuntu 22.04, rf → rapidfort ubuntu
//
// The RedHat feed repeats its rf and fcNN ranges under every RHEL major, so the identical copies collapse into one.
func (vs VulnSrc) split(eco ecosystem.Type, src SourcePackageAdvisory, path string) map[bucket.DataSourceBucket]map[string]CVEEntry {
	out := map[bucket.DataSourceBucket]map[string]CVEEntry{}
	// Walk the version keys in a stable order — the Advisory is written to disk verbatim, so its event order must be deterministic.
	ecoVers := make([]string, 0, len(src.Advisory))
	for ecoVer := range src.Advisory {
		ecoVers = append(ecoVers, ecoVer)
	}
	sort.Strings(ecoVers)

	for _, ecoVer := range ecoVers {
		for cveID, cve := range src.Advisory[ecoVer] {
			for _, ev := range cve.Events {
				if ev.Introduced == "" && ev.Fixed == "" {
					continue
				}
				b, err := resolveBucket(eco, ecoVer, ev.Identifier)
				if err != nil {
					vs.logger.Warn("Skipping range", "path", path, "cve", cveID, "err", err)
					continue
				}
				cveMap, ok := out[b]
				if !ok {
					cveMap = map[string]CVEEntry{}
					out[b] = cveMap
				}
				// Copy the CVE meta on first sight, then collect its events.
				e, ok := cveMap[cveID]
				if !ok {
					e = cve
					e.Events = nil
				}
				// Skip the identical copies the feed repeats under every version key.
				if !slices.Contains(e.Events, ev) {
					e.Events = append(e.Events, ev)
				}
				cveMap[cveID] = e
			}
		}
	}
	return out
}

// resolveBucket works out which bucket one range belongs to, failing for ranges trivy-db can't dispatch.
// eco and ecoVer are the OS of the feed and the version key the range is listed under; the identifier can override both.
func resolveBucket(eco ecosystem.Type, ecoVer, identifier string) (bucket.DataSourceBucket, error) {
	eb := oops.With("identifier", identifier)
	switch {
	// RapidFort's rebuilds are not tied to a distro release: they keep the feed's OS but drop the version.
	case identifier == rapidFortIdentifier:
		ecoVer = ""
	// A feed tags its own distribution's packages by name ("ubuntu", "debian") or
	// not at all (alpine): either way they belong to the release the file lists them under.
	case identifier == string(eco), identifier == "":
		// Keep eco and ecoVer as the feed listed them.
	// "elN" is the dist tag of the Enterprise Linux family, which RedHat, Oracle and the other rebuilds all share, so it names the release while the feed still names the distribution.
	case strings.HasPrefix(identifier, redHatIdentifier):
		ecoVer = strings.TrimPrefix(identifier, redHatIdentifier)
	// Amazon Linux tags its releases "amzn2"/"amzn2023" instead of elN, and likewise only names the release.
	case strings.HasPrefix(identifier, amazonIdentifier):
		ecoVer = strings.TrimPrefix(identifier, amazonIdentifier)
	// "fcNN" names Fedora itself, which the RPM feeds carry alongside their own ranges.
	case strings.HasPrefix(identifier, fedoraIdentifier):
		eco, ecoVer = ecosystem.Fedora, strings.TrimPrefix(identifier, fedoraIdentifier)
	// The identifiers of the other feeds have to be added above as they appear — an unknown one is dropped rather than guessed.
	default:
		return nil, eb.Errorf("unusable distribution identifier")
	}

	// Only the rebuilds are release-less; every other range has to name a release, so a bare dist tag ("el", "fc") or an empty version key is rejected rather than folded into a rebuild bucket.
	if identifier != rapidFortIdentifier && !isVersionNumber(ecoVer) {
		return nil, eb.With("version", ecoVer).Errorf("unusable distribution version")
	}
	return newBucket(eco, ecoVer)
}

// isVersionNumber reports whether s looks like a distro version number:
// dot-separated groups of digits, e.g. "9", "44" or "3.18". Empty, leading,
// trailing or doubled dots (e.g. "", ".", "1.", "1..2") are rejected so a
// malformed identifier (e.g. "fcrawhide") or version key can't produce a bogus
// bucket like "rapidfort fedora rawhide".
func isVersionNumber(s string) bool {
	if s == "" {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if part == "" {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func (vs VulnSrc) put(entries []entry) error {
	// Fail loudly on an empty parse — a silent no-op here would ship an empty
	// RapidFort integration if the cache is misconfigured or the feed breaks.
	if len(entries) == 0 {
		return oops.Errorf("no RapidFort advisories to save — check that the rapidfort-security-advisories cache is populated")
	}
	vs.logger.Info("Saving RapidFort advisories", "count", len(entries))

	return vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		// Register the data source once per platform.
		addedDataSources := map[string]struct{}{}
		for _, e := range entries {
			// Name() concatenates the platform string, so compute it once and reuse.
			platform := e.bucket.Name()
			eb := oops.With("platform", platform).With("package", e.pkgName).With("cve", e.cveID)

			if _, ok := addedDataSources[platform]; !ok {
				if err := vs.dbc.PutDataSource(tx, platform, e.bucket.DataSource()); err != nil {
					return eb.Wrapf(err, "failed to put data source")
				}
				addedDataSources[platform] = struct{}{}
			}

			if err := vs.dbc.PutAdvisoryDetail(tx, e.cveID, e.pkgName, []string{platform}, e.advisory); err != nil {
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

// buildAdvisory converts version-range events into the trivy-db Advisory format.
// Each event represents a version range: Introduced..Fixed (or open-ended if
// Fixed is empty). Buckets are homogeneous per distribution, so no per-range
// distribution metadata is stored alongside the ranges.
func buildAdvisory(cve CVEEntry) types.Advisory {
	var patched, vulnerable []string
	for _, ev := range cve.Events {
		switch {
		case ev.Fixed != "":
			patched = append(patched, ev.Fixed)
			// A lower bound of zero ("0:0" once the feed spells out the epoch) means the same as no lower bound,
			// so it is left out — as `osv` package does for the same case.
			if introduced := ev.Introduced; introduced != "" && introduced != "0" && introduced != "0:0" {
				vulnerable = append(vulnerable, fmt.Sprintf(">=%s, <%s", introduced, ev.Fixed))
			} else {
				vulnerable = append(vulnerable, fmt.Sprintf("<%s", ev.Fixed))
			}
		case ev.Introduced != "":
			// An open vulnerability keeps its lower bound even when it is zero: dropping it would leave nothing to write.
			vulnerable = append(vulnerable, fmt.Sprintf(">=%s", ev.Introduced))
		}
	}

	sev := types.SeverityUnknown
	if s, err := types.NewSeverity(strings.ToUpper(cve.Severity)); err == nil {
		sev = s
	}

	// Sort for a stable on-disk DB: events for the same distribution can be
	// collected from several version keys of the file (see split), so their
	// source order is not guaranteed. The lists are independent (no per-range
	// identifiers), so sorting each on its own is safe.
	sort.Strings(patched)
	// The feed lists one event per historical rebuild, all carrying the same fix, so the fixed version has to be collapsed — the scanner prints this list as is.
	// The vulnerable ranges stay: those events differ in their lower bound, and each one describes a real interval.
	patched = slices.Compact(patched)
	sort.Strings(vulnerable)

	return types.Advisory{
		PatchedVersions:    patched,
		VulnerableVersions: vulnerable,
		// RapidFort rates each package on its own, so the severity belongs here rather than in the CVE-wide VulnerabilityDetail.
		Severity: sev,
	}
}

// buildVulnerabilityDetail carries only prose (title, description). Severity stays in Advisory (per-package).
func buildVulnerabilityDetail(cve CVEEntry) types.VulnerabilityDetail {
	return types.VulnerabilityDetail{
		Title:       cve.Title,
		Description: cve.Description,
	}
}

// VulnSrcGetter is used by trivy (the scanner) to query advisories from the DB
// for a specific base ecosystem (e.g. ecosystem.Ubuntu, ecosystem.Alpine).
type VulnSrcGetter struct {
	baseEcosystem ecosystem.Type
	config
}

func NewVulnSrcGetter(baseEcosystem ecosystem.Type) VulnSrcGetter {
	return VulnSrcGetter{
		baseEcosystem: baseEcosystem,
		config: config{
			dbc:    db.Config{},
			logger: log.WithPrefix("rapidfort-" + string(baseEcosystem)),
		},
	}
}

// Get returns RapidFort advisories for a given package and OS version (e.g. "22.04").
// RapidFort's own rebuilds are not tied to a release, so pass an empty version to read them.
func (vs VulnSrcGetter) Get(params db.GetParams) ([]types.Advisory, error) {
	eb := oops.In("rapidfort").With("base_ecosystem", vs.baseEcosystem).With("os_version", params.Release).With("package_name", params.PkgName)

	b, err := newBucket(vs.baseEcosystem, params.Release)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to create a bucket name")
	}
	advs, err := vs.dbc.GetAdvisories(b.Name(), params.PkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get advisories")
	}
	return advs, nil
}
