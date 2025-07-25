package oracleoval

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	version "github.com/knqyf263/go-rpm-version"
	"github.com/samber/lo"
	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

var (
	// cat /etc/os-release ORACLE_BUGZILLA_PRODUCT="Oracle Linux 8"
	platformFormat  = "Oracle Linux %s"
	targetPlatforms = []string{"Oracle Linux 5", "Oracle Linux 6", "Oracle Linux 7", "Oracle Linux 8", "Oracle Linux 9"}
	oracleDir       = filepath.Join("oval", "oracle")

	source = types.DataSource{
		ID:   vulnerability.OracleOVAL,
		Name: "Oracle Linux OVAL definitions",
		URL:  "https://linux.oracle.com/security/oval/",
	}
)

type PutInput struct {
	VulnID     string                       // CVE-ID or ELSA-ID
	Vuln       types.VulnerabilityDetail    // vulnerability detail such as CVSS and description
	Advisories map[Package]types.Advisories // pkg => advisories
	OVALs      []OracleOVAL                 // for extensibility, not used in trivy-db
}

type DB interface {
	db.Operation
	db.Getter
	Put(*bolt.Tx, PutInput) error
}

type VulnSrc struct {
	DB     // Those who want to customize Trivy DB can override put/get methods.
	logger *log.Logger
}

type Oracle struct {
	db.Operation
}

func NewVulnSrc() *VulnSrc {
	return &VulnSrc{
		DB:     &Oracle{Operation: db.Config{}},
		logger: log.WithPrefix("oracle-oval"),
	}
}

func (vs *VulnSrc) Name() types.SourceID {
	return source.ID
}

func (vs *VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", oracleDir)
	eb := oops.In("oracle").Tags("oval").With("root_dir", rootDir)

	ovals, err := vs.parse(rootDir)
	if err != nil {
		return eb.Wrap(err)
	}
	if err = vs.put(ovals); err != nil {
		return eb.Wrapf(err, "put error")
	}

	return nil
}

// Parse parses all the advisories from Alma Linux.
// It is exported for those who want to customize trivy-db.
func (vs *VulnSrc) parse(rootDir string) ([]OracleOVAL, error) {
	var ovals []OracleOVAL
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var oval OracleOVAL
		if err := json.NewDecoder(r).Decode(&oval); err != nil {
			return oops.With("file_path", path).Wrapf(err, "json decode error")
		}
		ovals = append(ovals, oval)
		return nil
	})
	if err != nil {
		return nil, oops.Wrapf(err, "walk error")
	}

	return ovals, nil
}

func (vs *VulnSrc) put(ovals []OracleOVAL) error {
	vs.logger.Info("Saving Oracle Linux OVAL")

	err := vs.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, ovals)
	})
	if err != nil {
		return oops.Wrapf(err, "batch update error")
	}

	return nil
}

func (vs *VulnSrc) commit(tx *bolt.Tx, ovals []OracleOVAL) error {
	// CVE -> PutInput
	putInputs := make(map[string]PutInput)
	for _, oval := range ovals {
		elsaID := strings.Split(oval.Title, ":")[0]

		var vulnIDs []string
		for _, cve := range oval.Cves {
			vulnIDs = append(vulnIDs, cve.ID)
		}
		if len(vulnIDs) == 0 {
			vulnIDs = append(vulnIDs, elsaID)
		}

		advisories := map[Package]types.Advisories{}
		affectedPkgs := walkOracle(oval.Criteria, "", "", []AffectedPackage{})
		for _, affectedPkg := range affectedPkgs {
			// there are cases when advisory doesn't have arch
			// it looks as bug
			// because CVE doesn't contain this ELSA
			// e.g. https://linux.oracle.com/errata/ELSA-2018-0013.html
			// https://linux.oracle.com/cve/CVE-2017-5715.html
			if affectedPkg.Package.Name == "" || affectedPkg.Arch == "" {
				continue
			}

			platformName := affectedPkg.Package.PlatformName()
			if !slices.Contains(targetPlatforms, platformName) {
				continue
			}

			if err := vs.PutDataSource(tx, platformName, source); err != nil {
				return oops.With("platform", platformName).Wrapf(err, "failed to put data source")
			}

			advs := types.Advisories{
				Entries: []types.Advisory{
					{
						FixedVersion: affectedPkg.FixedVersion,
						Arches: []string{
							affectedPkg.Arch,
						},
						VendorIDs: []string{
							elsaID,
						},
					},
				},
			}
			if savedAdvs, ok := advisories[affectedPkg.Package]; ok {
				advs.Entries = append(advs.Entries, savedAdvs.Entries...)
			}
			advisories[affectedPkg.Package] = advs
		}

		var references []string
		for _, ref := range oval.References {
			references = append(references, ref.URI)
		}

		for _, vulnID := range vulnIDs {
			vuln := types.VulnerabilityDetail{
				Description: oval.Description,
				References:  referencesFromContains(references, []string{elsaID, vulnID}),
				Title:       oval.Title,
				Severity:    severityFromThreat(oval.Severity),
			}

			input := PutInput{
				VulnID:     vulnID,
				Vuln:       vuln,
				Advisories: maps.Clone(advisories),
				OVALs:      []OracleOVAL{oval},
			}

			if savedInput, ok := putInputs[input.VulnID]; ok {
				input.OVALs = append(input.OVALs, savedInput.OVALs...)

				for inputPkg, inputAdvs := range input.Advisories {
					if savedPkgAdvs, pkgFound := savedInput.Advisories[inputPkg]; pkgFound {
						inputAdvs.Entries = append(savedPkgAdvs.Entries, inputAdvs.Entries...)
					}
					savedInput.Advisories[inputPkg] = inputAdvs
				}
				input.Advisories = savedInput.Advisories
			}
			putInputs[input.VulnID] = input
		}
	}

	for _, input := range putInputs {
		for pkg, advs := range input.Advisories {
			input.Advisories[pkg] = mergeAdvisoriesEntries(advs)
		}

		if err := vs.Put(tx, input); err != nil {
			return oops.Wrapf(err, "db put error")
		}
	}

	return nil
}

type archFlavor struct {
	Arch   string
	Flavor PkgFlavor
}

type versionVendorID struct {
	Version  string
	VendorID string
}

// mergeAdvisoriesEntries merges advisories by picking the latest version (with vendorID) for each arch+flavor.
// There may be multiple advisories that fix the same vulnerability, possibly providing multiple fixed versions.
// In this case, we need to determine the "latest" version, which is now defined as the highest (greatest) version number.
//
// Additionally, we choose a single fixed version for backward compatibility, which is derived from
// the highest normal flavor version on the x86_64 architecture if available.
func mergeAdvisoriesEntries(advisories types.Advisories) types.Advisories {
	// Step 1: Select the latest version per (arch, flavor)
	latestVersions := selectLatestVersions(advisories)

	// Step 2: Aggregate arches by their chosen version + vendorID
	versionToArches := make(map[versionVendorID][]string)
	for k, v := range latestVersions {
		versionToArches[v] = append(versionToArches[v], k.Arch)
	}

	// Step 3: Build final entries, sorted by version
	entries := lo.MapToSlice(versionToArches, func(ver versionVendorID, arches []string) types.Advisory {
		sort.Strings(arches)
		return types.Advisory{
			FixedVersion: ver.Version,
			Arches:       arches,
			VendorIDs: []string{
				ver.VendorID,
			},
		}
	})
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].FixedVersion < entries[j].FixedVersion // Sorting lexicographically
	})

	return types.Advisories{
		FixedVersion: determinePrimaryFixedVersion(latestVersions), // For backward compatibility
		Entries:      entries,
	}
}

// selectLatestVersions selects the latest (highest) version per (arch, flavor)
func selectLatestVersions(advisories types.Advisories) map[archFlavor]versionVendorID {
	latestVersions := make(map[archFlavor]versionVendorID) // key: archFlavor -> highest fixedVersion
	for _, entry := range advisories.Entries {
		if len(entry.Arches) == 0 || entry.FixedVersion == "" {
			continue
		}
		arch := entry.Arches[0]        // Before merging `arches`, it always contains only 1 arch
		vendorID := entry.VendorIDs[0] // Before merging `VendorIDs`, it always contains only 1 elsaID
		flavor := PackageFlavor(entry.FixedVersion)
		key := archFlavor{
			Arch:   arch,
			Flavor: flavor,
		}

		currentVer := version.NewVersion(entry.FixedVersion)
		if existing, ok := latestVersions[key]; !ok || currentVer.GreaterThan(version.NewVersion(existing.Version)) {
			// Keep the higher (latest) version
			latestVersions[key] = versionVendorID{
				Version:  entry.FixedVersion,
				VendorID: vendorID,
			}
		}
	}
	return latestVersions
}

// determinePrimaryFixedVersion determines primary fixed version for backward compatibility
// It is chosen as the highest normal flavor version on x86_64 if any exist.
// If no normal flavor version exists, the maximum version in lexical order is chosen.
func determinePrimaryFixedVersion(latestVersions map[archFlavor]versionVendorID) string {
	primaryFixedVersion := latestVersions[archFlavor{
		Arch:   "x86_64",
		Flavor: NormalPackageFlavor,
	}]
	if primaryFixedVersion.Version == "" {
		vers := lo.MapToSlice(latestVersions, func(_ archFlavor, v versionVendorID) string {
			return v.Version
		})
		primaryFixedVersion.Version = lo.Max(vers) // Chose the maximum value in lexical order for idempotency
	}
	return primaryFixedVersion.Version
}

type PkgFlavor string

const (
	NormalPackageFlavor  PkgFlavor = "normal"
	FipsPackageFlavor    PkgFlavor = "fips"
	KsplicePackageFlavor PkgFlavor = "ksplice"
)

// PackageFlavor determinants the package "flavor" based on its version string
//   - normal
//   - FIPS validated
//   - ksplice userspace
func PackageFlavor(version string) PkgFlavor {
	version = strings.ToLower(version)
	if strings.HasSuffix(version, "_fips") {
		return FipsPackageFlavor
	}

	subs := strings.Split(version, ".")
	for _, s := range subs {
		if strings.HasPrefix(s, "ksplice") {
			return KsplicePackageFlavor
		}
	}
	return NormalPackageFlavor
}

func (o *Oracle) Put(tx *bolt.Tx, input PutInput) error {
	eb := oops.With("vuln_id", input.VulnID)
	if err := o.PutVulnerabilityDetail(tx, input.VulnID, source.ID, input.Vuln); err != nil {
		return eb.Wrapf(err, "failed to save vulnerability detail")
	}

	// for optimization
	if err := o.PutVulnerabilityID(tx, input.VulnID); err != nil {
		return eb.Wrapf(err, "failed to save vulnerability ID")
	}

	for pkg, advisory := range input.Advisories {
		advisory = removeVendorIDs(advisory)
		platformName := pkg.PlatformName()
		if err := o.PutAdvisoryDetail(tx, input.VulnID, pkg.Name, []string{platformName}, advisory); err != nil {
			return eb.With("package_name", pkg.Name).With("bucket_name", platformName).Wrapf(err, "failed to save advisory")
		}
	}
	return nil
}

// removeVendorIDs removes VendorID from advisories + merges arches for advisories (by fixedVersion).
// This is needed to save space in OSS trivy-db.
// But Aqua storage requires this information.
func removeVendorIDs(advs types.Advisories) types.Advisories {
	versionToArches := make(map[string][]string) // fixed version -> arches
	for _, entry := range advs.Entries {
		versionToArches[entry.FixedVersion] = append(versionToArches[entry.FixedVersion], entry.Arches...)
	}

	entries := lo.MapToSlice(versionToArches, func(ver string, arches []string) types.Advisory {
		sort.Strings(arches)
		return types.Advisory{
			FixedVersion: ver,
			Arches:       arches,
		}
	})
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].FixedVersion < entries[j].FixedVersion // Sorting lexicographically
	})

	advs.Entries = entries
	return advs
}

func (o *Oracle) Get(params db.GetParams) ([]types.Advisory, error) {
	eb := oops.In("oracle").Tags("oval").With("release", params.Release).With("package_name", params.PkgName).With("arch", params.Arch)
	bucket := fmt.Sprintf(platformFormat, params.Release)
	rawAdvisories, err := o.ForEachAdvisory([]string{bucket}, params.PkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "unable to iterate advisories")
	}
	var advisories []types.Advisory
	for vulnID, v := range rawAdvisories {
		var adv types.Advisories
		if err = json.Unmarshal(v.Content, &adv); err != nil {
			return nil, eb.Wrapf(err, "json unmarshal error")
		}

		// For backward compatibility (This code can be deleted after Dec 19th, 2024)
		// The old trivy-db has no entries, but has fixed versions and custom fields.
		if len(adv.Entries) == 0 {
			advisories = append(advisories, types.Advisory{
				VulnerabilityID: vulnID,
				FixedVersion:    adv.FixedVersion,
				DataSource:      &v.Source,
				Custom:          adv.Custom,
			})
			continue
		}

		for _, entry := range adv.Entries {
			if !slices.Contains(entry.Arches, params.Arch) {
				continue
			}

			entry.VulnerabilityID = vulnID
			entry.DataSource = &v.Source
			advisories = append(advisories, entry)
		}
	}

	return advisories, nil
}

func walkOracle(cri Criteria, osVer, arch string, pkgs []AffectedPackage) []AffectedPackage {
	for _, c := range cri.Criterions {
		if strings.HasPrefix(c.Comment, "Oracle Linux ") &&
			strings.HasSuffix(c.Comment, " is installed") {
			osVer = strings.TrimSuffix(strings.TrimPrefix(c.Comment, "Oracle Linux "), " is installed")
		}
		if strings.HasPrefix(c.Comment, "Oracle Linux arch is ") {
			arch = strings.TrimPrefix(c.Comment, "Oracle Linux arch is ")
		}
		ss := strings.Split(c.Comment, " is earlier than ")
		if len(ss) != 2 {
			continue
		}

		pkgs = append(pkgs, AffectedPackage{
			Package: Package{
				Name:  ss[0],
				OSVer: osVer,
			},
			Arch:         arch,
			FixedVersion: version.NewVersion(ss[1]).String(),
		})
	}

	for _, c := range cri.Criterias { //nolint:misspell
		pkgs = walkOracle(c, osVer, arch, pkgs)
	}
	return pkgs
}

func referencesFromContains(sources, matches []string) []string {
	var references []string
	for _, s := range sources {
		for _, m := range matches {
			if strings.Contains(s, m) {
				references = append(references, s)
			}
		}
	}

	references = lo.Uniq(references)
	slices.Sort(references)

	return references
}

func severityFromThreat(sev string) types.Severity {
	switch sev {
	case "LOW":
		return types.SeverityLow
	case "MODERATE":
		return types.SeverityMedium
	case "IMPORTANT":
		return types.SeverityHigh
	case "CRITICAL":
		return types.SeverityCritical
	}
	return types.SeverityUnknown
}
