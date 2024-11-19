package oracleoval

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"slices"
	"strings"

	version "github.com/knqyf263/go-rpm-version"
	"github.com/samber/lo"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/exp/maps"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
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
	Put(*bolt.Tx, PutInput) error
	Get(release, pkgName string) ([]types.Advisory, error)
}

type VulnSrc struct {
	DB // Those who want to customize Trivy DB can override put/get methods.
}

type Oracle struct {
	db.Operation
}

func NewVulnSrc() *VulnSrc {
	return &VulnSrc{
		DB: &Oracle{Operation: db.Config{}},
	}
}

func (vs *VulnSrc) Name() types.SourceID {
	return source.ID
}

func (vs *VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", oracleDir)
	ovals, err := vs.parse(rootDir)
	if err != nil {
		return err
	}
	if err = vs.put(ovals); err != nil {
		return xerrors.Errorf("error in Oracle Linux OVAL save: %w", err)
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
			return xerrors.Errorf("failed to decode Oracle Linux OVAL JSON: %w", err)
		}
		ovals = append(ovals, oval)
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("error in Oracle Linux OVAL walk: %w", err)
	}

	return ovals, nil
}

func (vs *VulnSrc) put(ovals []OracleOVAL) error {
	log.Println("Saving Oracle Linux OVAL")

	err := vs.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, ovals)
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
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
		affectedPkgs := walkOracle(oval.Criteria, "", []AffectedPackage{})
		for _, affectedPkg := range affectedPkgs {
			if affectedPkg.Package.Name == "" {
				continue
			}

			platformName := affectedPkg.Package.PlatformName()
			if !slices.Contains(targetPlatforms, platformName) {
				continue
			}

			if err := vs.PutDataSource(tx, platformName, source); err != nil {
				return xerrors.Errorf("failed to put data source: %w", err)
			}

			advs := types.Advisories{
				Entries: []types.Advisory{
					{
						FixedVersion: affectedPkg.FixedVersion,
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
			input.Advisories[pkg] = resolveAdvisoriesEntries(advs)
		}

		err := vs.Put(tx, input)
		if err != nil {
			return xerrors.Errorf("db put error: %w", err)
		}
	}

	return nil
}

// resolveAdvisoriesEntries removes entries with the same fixedVersion.
// Additionally, it only selects the latest fixedVersion for each flavor.
func resolveAdvisoriesEntries(advisories types.Advisories) types.Advisories {
	fixedVersions := lo.Map(advisories.Entries, func(entry types.Advisory, _ int) string {
		return entry.FixedVersion
	})
	fixedVer, resolvedVers := resolveVersions(fixedVersions)
	entries := lo.Map(resolvedVers, func(ver string, _ int) types.Advisory {
		return types.Advisory{
			FixedVersion: ver,
		}
	})
	return types.Advisories{
		FixedVersion: fixedVer,
		Entries:      entries,
	}
}

// resolveVersions removes duplicates and returns normal flavor + only one version for each flavor.
func resolveVersions(vers []string) (string, []string) {
	vers = lo.Uniq(vers)

	fixedVers := make(map[PkgFlavor]string)
	for _, ver := range vers {
		flavor := PackageFlavor(ver)
		if savedVer, ok := fixedVers[flavor]; ok {
			v := version.NewVersion(ver)
			sv := version.NewVersion(savedVer)
			if v.LessThan(sv) {
				ver = savedVer
			}
		}
		fixedVers[flavor] = ver
	}

	versions := lo.Values(fixedVers)
	slices.Sort(versions)

	fixedVersion, ok := fixedVers[NormalPackageFlavor]
	// To keep the previous logic - use the ksplice/fips version if the normal flavor doesn't exist.
	if !ok {
		fixedVersion = versions[0]
	}

	return fixedVersion, versions
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
	if err := o.PutVulnerabilityDetail(tx, input.VulnID, source.ID, input.Vuln); err != nil {
		return xerrors.Errorf("failed to save Oracle Linux OVAL vulnerability: %w", err)
	}

	// for optimization
	if err := o.PutVulnerabilityID(tx, input.VulnID); err != nil {
		return xerrors.Errorf("failed to save %s: %w", input.VulnID, err)
	}

	for pkg, advisory := range input.Advisories {
		platformName := pkg.PlatformName()
		if err := o.PutAdvisoryDetail(tx, input.VulnID, pkg.Name, []string{platformName}, advisory); err != nil {
			return xerrors.Errorf("failed to save Oracle Linux advisory: %w", err)
		}
	}
	return nil
}

func (o *Oracle) Get(release string, pkgName string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, release)
	rawAdvisories, err := o.ForEachAdvisory([]string{bucket}, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("unable to iterate advisories: %w", err)
	}
	var advisories []types.Advisory
	for vulnID, v := range rawAdvisories {
		var adv types.Advisories
		if err = json.Unmarshal(v.Content, &adv); err != nil {
			return nil, xerrors.Errorf("failed to unmarshal advisory JSON: %w", err)
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
			entry.VulnerabilityID = vulnID
			entry.DataSource = &v.Source
			advisories = append(advisories, entry)
		}
	}

	return advisories, nil
}

func walkOracle(cri Criteria, osVer string, pkgs []AffectedPackage) []AffectedPackage {
	for _, c := range cri.Criterions {
		if strings.HasPrefix(c.Comment, "Oracle Linux ") &&
			strings.HasSuffix(c.Comment, " is installed") {
			osVer = strings.TrimSuffix(strings.TrimPrefix(c.Comment, "Oracle Linux "), " is installed")
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
			FixedVersion: version.NewVersion(ss[1]).String(),
		})
	}

	for _, c := range cri.Criterias {
		pkgs = walkOracle(c, osVer, pkgs)
	}
	return pkgs
}

func referencesFromContains(sources []string, matches []string) []string {
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
