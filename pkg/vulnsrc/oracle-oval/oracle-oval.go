package oracleoval

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"slices"
	"strings"

	"github.com/samber/lo"

	version "github.com/knqyf263/go-rpm-version"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	ustrings "github.com/aquasecurity/trivy-db/pkg/utils/strings"
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
	VulnID       string                      // CVE-ID or ELSA-ID
	PlatformName string                      // Oracle Linux 5/6/7...
	Vuln         types.VulnerabilityDetail   // vulnerability detail such as CVSS and description
	Advisories   map[string]types.Advisories // pkgName => advisories
	OVAL         OracleOVAL                  // for extensibility, not used in trivy-db
}

type DB interface {
	db.Operation
	Put(*bolt.Tx, PutInput) error
	Get(release, pkgName, arch string) ([]types.Advisory, error)
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
	foundPlatformNames := map[string]struct{}{}
	// platform => vulnID => PutInput
	savedInputs := map[string]map[string]PutInput{}
	for _, oval := range ovals {
		elsaID := strings.Split(oval.Title, ":")[0]

		var vulnIDs []string
		for _, cve := range oval.Cves {
			vulnIDs = append(vulnIDs, cve.ID)
		}
		if len(vulnIDs) == 0 {
			vulnIDs = append(vulnIDs, elsaID)
		}

		for _, vulnID := range vulnIDs {
			affectedPkgs := walkOracle(oval.Criteria, "", "", []AffectedPackage{})
			for _, affectedPkg := range affectedPkgs {
				pkgName := affectedPkg.Package.Name
				// there are cases when advisory doesn't have arch
				// it looks as bug
				// because CVE doesn't contain this ELSA
				// e.g. https://linux.oracle.com/errata/ELSA-2018-0013.html
				// https://linux.oracle.com/cve/CVE-2017-5715.html
				if pkgName == "" || affectedPkg.Arch == "" {
					continue
				}

				platformName := affectedPkg.PlatformName()
				if !slices.Contains(targetPlatforms, platformName) {
					continue
				}

				// save unique platform name
				// will save datasources for these platforms later
				if _, ok := foundPlatformNames[platformName]; !ok {
					foundPlatformNames[platformName] = struct{}{}
				}

				input := PutInput{
					Advisories: map[string]types.Advisories{},
				}
				savedPlatformVulns := map[string]PutInput{}
				if savedVulns, ok := savedInputs[platformName]; ok {
					savedPlatformVulns = savedVulns
					if in, ok := savedVulns[vulnID]; ok {
						input = in
					}
				}

				entry := types.Advisory{
					FixedVersion: affectedPkg.Package.FixedVersion,
					Arches:       []string{affectedPkg.Arch},
					VendorIDs:    []string{elsaID},
				}

				// if the advisory for this package and CVE have been kept - just add the new architecture
				if adv, ok := input.Advisories[pkgName]; ok {
					// update `fixedVersion` if `fixedVersion` for `x86_64` was not previously saved
					adv.FixedVersion = fixedVersion(adv.FixedVersion, entry.FixedVersion, affectedPkg.Arch)

					old, i, found := lo.FindIndexOf(adv.Entries, func(adv types.Advisory) bool {
						return adv.FixedVersion == entry.FixedVersion
					})

					// If the advisory with the same fixed version and ELSA-ID is present - just add the new architecture
					if found {
						if !slices.Contains(old.Arches, affectedPkg.Arch) {
							adv.Entries[i].Arches = append(old.Arches, affectedPkg.Arch)
						}
						if !slices.Contains(old.VendorIDs, elsaID) {
							adv.Entries[i].VendorIDs = append(old.VendorIDs, elsaID)
						}
						input.Advisories[pkgName] = adv
					} else if !found {
						adv.Entries = append(adv.Entries, entry)
						input.Advisories[pkgName] = adv
					}
				} else {
					input.Advisories[pkgName] = types.Advisories{
						// will save `0.0.0` version for non-`x86_64` arch
						// to avoid false positives when using old Trivy with new database
						FixedVersion: fixedVersion("0.0.0", entry.FixedVersion, affectedPkg.Arch), // For backward compatibility
						Entries:      []types.Advisory{entry},
					}
				}
				if len(input.Advisories) == 0 {
					continue
				}

				var references []string
				for _, ref := range oval.References {
					references = append(references, ref.URI)
				}

				vuln := types.VulnerabilityDetail{
					Description: oval.Description,
					References:  referencesFromContains(references, []string{elsaID, vulnID}),
					Title:       oval.Title,
					Severity:    severityFromThreat(oval.Severity),
				}

				input.VulnID = vulnID
				input.Vuln = vuln
				input.PlatformName = platformName

				savedPlatformVulns[vulnID] = input
				savedInputs[platformName] = savedPlatformVulns
			}
		}
	}

	for platformName := range foundPlatformNames {
		if err := vs.PutDataSource(tx, platformName, source); err != nil {
			return xerrors.Errorf("failed to put data source: %w", err)
		}
	}
	for _, pkgs := range savedInputs {
		for _, input := range pkgs {
			err := vs.Put(tx, input)
			if err != nil {
				return xerrors.Errorf("db put error: %w", err)
			}
		}
	}

	return nil
}

func (o *Oracle) Put(tx *bolt.Tx, input PutInput) error {
	if err := o.PutVulnerabilityDetail(tx, input.VulnID, source.ID, input.Vuln); err != nil {
		return xerrors.Errorf("failed to save Oracle Linux OVAL vulnerability: %w", err)
	}

	// for optimization
	if err := o.PutVulnerabilityID(tx, input.VulnID); err != nil {
		return xerrors.Errorf("failed to save %s: %w", input.VulnID, err)
	}

	for pkgName, advisory := range input.Advisories {
		if err := o.PutAdvisoryDetail(tx, input.VulnID, pkgName, []string{input.PlatformName}, advisory); err != nil {
			return xerrors.Errorf("failed to save Oracle Linux advisory: %w", err)
		}
	}
	return nil
}

func (o *Oracle) Get(release string, pkgName, arch string) ([]types.Advisory, error) {
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

		// For backward compatibility
		// The old trivy-db has no entries, but has fixed versions only.
		if len(adv.Entries) == 0 {
			advisories = append(advisories, types.Advisory{
				VulnerabilityID: vulnID,
				FixedVersion:    adv.FixedVersion,
				DataSource:      &v.Source,
			})
			continue
		}

		for _, entry := range adv.Entries {
			if !slices.Contains(entry.Arches, arch) {
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
			OSVer: osVer,
			Arch:  arch,
			Package: Package{
				Name:         ss[0],
				FixedVersion: version.NewVersion(ss[1]).String(),
			},
		})
	}

	for _, c := range cri.Criterias {
		pkgs = walkOracle(c, osVer, arch, pkgs)
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
	return ustrings.Unique(references)
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

// fixedVersion checks for the arch and only updates version for `x86_64`
// only used for types.Advisories.FixedVersion for backward compatibility
func fixedVersion(prevVersion, newVersion, arch string) string {
	if arch == "x86_64" || arch == "noarch" {
		return newVersion
	}
	return prevVersion
}
