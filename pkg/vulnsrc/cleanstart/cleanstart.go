package cleanstart

import (
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
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/osv"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

// cleanstartDir is where vuln-list-update writes CleanStart advisories, relative to the
// vuln-list repository root. Advisories live under {cleanstartDir}/advisories/{year}/.
const cleanstartDir = "cleanstart"

var (
	platformName = bucket.NewCleanStart("").Name()
	source       = types.DataSource{
		ID:   vulnerability.CleanStart,
		Name: "CleanStart Security Advisories",
		URL:  "https://github.com/cleanstart-dev/cleanstart-security-advisories",
	}
)

type VulnSrc struct {
	dbc    db.Operation
	logger *log.Logger
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc:    db.Config{},
		logger: log.WithPrefix("cleanstart"),
	}
}

func (vs VulnSrc) Name() types.SourceID {
	return source.ID
}

// Update reads every advisory under {dir}/vuln-list/cleanstart and writes it to the DB.
// CleanStart publishes OSV schema 1.7.x, so the shared osv.Entry type covers the format.
func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", cleanstartDir)
	eb := oops.In(string(source.ID)).With("root_dir", rootDir)

	var osvEntries []osv.Entry
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var osvEntry osv.Entry
		if err := json.NewDecoder(r).Decode(&osvEntry); err != nil {
			return eb.With("file_path", path).Wrapf(err, "json decode error")
		}
		osvEntries = append(osvEntries, osvEntry)
		return nil
	})
	if err != nil {
		return eb.Wrapf(err, "walk error")
	}

	if err = vs.save(osvEntries); err != nil {
		return eb.Wrapf(err, "save error")
	}

	return nil
}

func (vs VulnSrc) save(osvEntries []osv.Entry) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		if err := vs.dbc.PutDataSource(tx, platformName, source); err != nil {
			return oops.Wrapf(err, "failed to put data source")
		}
		for _, osvEntry := range osvEntries {
			for _, e := range vs.convert(osvEntry) {
				if err := vs.put(tx, e); err != nil {
					return oops.With("vuln_id", e.vulnID).With("package_name", e.pkgName).Wrap(err)
				}
			}
		}
		return nil
	})
	if err != nil {
		return oops.Wrapf(err, "batch update failed")
	}
	return nil
}

func (vs VulnSrc) put(tx *bolt.Tx, e entry) error {
	if err := vs.dbc.PutAdvisoryDetail(tx, e.vulnID, e.pkgName, []string{platformName}, e.advisory); err != nil {
		return oops.Wrapf(err, "failed to save advisory detail")
	}

	// CleanStart IDs appear in neither NVD nor GHSA, so this source has to supply the
	// title and description itself. For CVEs and GHSAs it is only a fallback, since
	// those sources rank higher in vulnerability.AllSourceIDs.
	if err := vs.dbc.PutVulnerabilityDetail(tx, e.vulnID, source.ID, e.detail); err != nil {
		return oops.Wrapf(err, "failed to save vulnerability detail")
	}

	// Optimization: store only the vulnerabilities CleanStart actually ships a fix for.
	if err := vs.dbc.PutVulnerabilityID(tx, e.vulnID); err != nil {
		return oops.Wrapf(err, "failed to save vulnerability ID")
	}
	return nil
}

// convert expands one advisory into an entry per (vulnerability ID, package).
func (vs VulnSrc) convert(osvEntry osv.Entry) []entry {
	if osvEntry.Withdrawn != nil {
		return nil
	}

	fixed := vs.fixedVersions(osvEntry)
	if len(fixed) == 0 {
		return nil
	}

	ids := vulnIDs(osvEntry)
	if len(ids) == 0 {
		vs.logger.Warn("Skipping advisory without a usable vulnerability ID", "advisory_id", osvEntry.ID)
		return nil
	}

	detail := types.VulnerabilityDetail{
		Title:       osvEntry.Summary,
		Description: osvEntry.Details,
		References:  references(osvEntry),
	}

	// Sorted so that rebuilding the DB produces the same bucket contents every time.
	pkgNames := slices.Sorted(maps.Keys(fixed))

	entries := make([]entry, 0, len(ids)*len(pkgNames))
	for _, vulnID := range ids {
		for _, pkgName := range pkgNames {
			entries = append(entries, entry{
				vulnID:   vulnID,
				pkgName:  pkgName,
				advisory: types.Advisory{FixedVersion: fixed[pkgName]},
				detail:   detail,
			})
		}
	}
	return entries
}

// fixedVersions returns the fixed version per package.
//
// An advisory may list the same package more than once, once per build that carried the
// fix (e.g. linkerd2 at both 26.1.4-r0 and 26.4.2). trivy-db stores a single fixed
// version per (vulnerability, package) and the CleanStart bucket has no version
// dimension, so the lowest one wins: CleanStart is a single rolling stream, so every
// build at or above the first fixed version already contains the fix.
func (vs VulnSrc) fixedVersions(osvEntry osv.Entry) map[string]string {
	fixed := make(map[string]string)
	for _, affected := range osvEntry.Affected {
		// The feed is CleanStart-only today, but guard anyway so that a stray upstream
		// ecosystem never lands in the CleanStart OS bucket.
		if !strings.EqualFold(affected.Package.Ecosystem, ecosystemName) {
			continue
		}
		pkgName := affected.Package.Name
		if pkgName == "" {
			continue
		}
		for _, ver := range fixedVersionsInRanges(affected.Ranges) {
			if cur, ok := fixed[pkgName]; !ok || lessThan(ver, cur) {
				fixed[pkgName] = ver
			}
		}
	}
	return fixed
}

func fixedVersionsInRanges(ranges []osv.Range) []string {
	var versions []string
	for _, r := range ranges {
		if r.Type != rangeTypeEcosystem {
			continue
		}
		for _, event := range r.Events {
			if event.Fixed != "" {
				versions = append(versions, event.Fixed)
			}
		}
	}
	return versions
}

// lessThan compares two APK versions. Versions that fail to parse sort last, so a valid
// version is always preferred over a malformed one.
func lessThan(a, b string) bool {
	av, aErr := apkver.NewVersion(a)
	bv, bErr := apkver.NewVersion(b)
	switch {
	case aErr != nil && bErr != nil:
		return a < b
	case aErr != nil:
		return false
	case bErr != nil:
		return true
	}
	return av.LessThan(bv)
}

// vulnIDs picks the IDs the finding is reported under.
//
// Upstream CVEs win, because NVD and Red Hat supply severity and description for them.
// Any other upstream ID (a GHSA, typically) is used when the advisory carries no CVE,
// and the CleanStart ID only when there is no upstream at all. Reporting under both the
// upstream ID and the CleanStart ID would surface the same fix twice for one package.
func vulnIDs(osvEntry osv.Entry) []string {
	var cves, others []string
	for _, id := range osvEntry.Upstream {
		id = normalizeID(id)
		switch {
		case id == "":
			continue
		case strings.HasPrefix(id, "CVE-"):
			cves = append(cves, id)
		default:
			others = append(others, id)
		}
	}

	switch {
	case len(cves) > 0:
		return lo.Uniq(cves)
	case len(others) > 0:
		return lo.Uniq(others)
	case osvEntry.ID != "":
		return []string{osvEntry.ID}
	}
	return nil
}

// normalizeID upper-cases the prefix of an advisory ID so that it matches how the rest
// of trivy-db keys the same vulnerability. CleanStart emits ghsa-hr2v-4r36-88hr, while
// GHSA advisories are stored as GHSA-hr2v-4r36-88hr: the prefix is upper-case but the
// body is not, so the ID cannot simply be upper-cased as a whole.
func normalizeID(id string) string {
	id = strings.TrimSpace(id)
	prefix, rest, found := strings.Cut(id, "-")
	if !found {
		return strings.ToUpper(id)
	}
	return strings.ToUpper(prefix) + "-" + rest
}

func references(osvEntry osv.Entry) []string {
	var refs []string
	for _, ref := range osvEntry.References {
		if ref.URL != "" {
			refs = append(refs, ref.URL)
		}
	}
	return lo.Uniq(refs)
}

func (vs VulnSrc) Get(params db.GetParams) ([]types.Advisory, error) {
	eb := oops.In(string(source.ID))
	advisories, err := vs.dbc.GetAdvisories(platformName, params.PkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get advisories")
	}
	return advisories, nil
}
