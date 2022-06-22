package oracleoval

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"

	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	ustrings "github.com/aquasecurity/trivy-db/pkg/utils/strings"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	version "github.com/knqyf263/go-rpm-version"
	"golang.org/x/xerrors"
)

var (
	// cat /etc/os-release ORACLE_BUGZILLA_PRODUCT="Oracle Linux 8"
	platformFormat  = "Oracle Linux %s"
	targetPlatforms = []string{"Oracle Linux 5", "Oracle Linux 6", "Oracle Linux 7", "Oracle Linux 8"}
	oracleDir       = filepath.Join("oval", "oracle")

	source = types.DataSource{
		ID:   vulnerability.OracleOVAL,
		Name: "Oracle Linux OVAL definitions",
		URL:  "https://linux.oracle.com/security/oval/",
	}
)

type VulnSrc struct {
	dbc db.Operation
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Name() types.SourceID {
	return source.ID
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", oracleDir)

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
		return xerrors.Errorf("error in Oracle Linux OVAL walk: %w", err)
	}

	if err = vs.save(ovals); err != nil {
		return xerrors.Errorf("error in Oracle Linux OVAL save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(ovals []OracleOVAL) error {
	log.Println("Saving Oracle Linux OVAL")

	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, ovals)
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}

	return nil

}

func (vs VulnSrc) commit(tx *bolt.Tx, ovals []OracleOVAL) error {
	advisories := map[bucket]Advisory{}
	vulnerabilityDetails := map[string]types.VulnerabilityDetail{}

	for _, oval := range ovals {
		elsaID := strings.Split(oval.Title, ":")[0]

		var vulnIDs []string
		for _, cve := range oval.Cves {
			vulnIDs = append(vulnIDs, cve.ID)

			vulnerabilityDetails[cve.ID] = mergeVulnerabilityDetails(vulnerabilityDetails[cve.ID], oval, []string{elsaID, cve.ID})
		}
		if len(vulnIDs) == 0 {
			vulnIDs = append(vulnIDs, elsaID)

			vulnerabilityDetails[elsaID] = mergeVulnerabilityDetails(vulnerabilityDetails[elsaID], oval, []string{elsaID})
		}

		affectedPkgs := walkOracle(oval.Criteria, "", []AffectedPackage{})
		for _, affectedPkg := range affectedPkgs {
			if affectedPkg.Package.Name == "" {
				continue
			}

			platformName := fmt.Sprintf(platformFormat, affectedPkg.OSVer)
			if !ustrings.InSlice(platformName, targetPlatforms) {
				continue
			}

			if err := vs.dbc.PutDataSource(tx, platformName, source); err != nil {
				return xerrors.Errorf("failed to put data source: %w", err)
			}

			for _, vulnID := range vulnIDs {
				bkt := bucket{
					platform: platformName,
					vulnID:   vulnID,
					pkgName:  affectedPkg.Package.Name,
				}
				advisories[bkt] = mergeEntries(advisories[bkt], affectedPkg, elsaID)
			}
		}
	}

	// Now that we've processed all the reports, we can save the vulnerability and advisory information
	for vulnID, details := range vulnerabilityDetails {
		if err := vs.dbc.PutVulnerabilityID(tx, vulnID); err != nil {
			return xerrors.Errorf("failed to save the vulnerability ID: %w", err)
		}

		if err := vs.dbc.PutVulnerabilityDetail(tx, vulnID, source.ID, details); err != nil {
			return xerrors.Errorf("failed to save Oracle Linux OVAL vulnerability: %w", err)
		}
	}

	for bkt, advisory := range advisories {
		if err := vs.dbc.PutAdvisoryDetail(tx, bkt.vulnID, bkt.pkgName, []string{bkt.platform}, advisory); err != nil {
			return xerrors.Errorf("failed to save Oracle Linux OVAL: %w", err)
		}
	}

	return nil
}

func (vs VulnSrc) Get(release string, pkgName string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, release)
	rawAdvisories, err := vs.dbc.ForEachAdvisory([]string{bucket}, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("unable to iterate advisories: %w", err)
	}

	var advisories []types.Advisory
	for vulnID, v := range rawAdvisories {
		if len(v.Content) == 0 {
			continue
		}

		var adv Advisory
		if err = json.Unmarshal(v.Content, &adv); err != nil {
			return nil, xerrors.Errorf("failed to unmarshal advisory JSON: %w", err)
		}

		for _, entry := range adv.Entries {
			advisory := types.Advisory{
				FixedVersion:    entry.FixedVersion,
				VulnerabilityID: vulnID,
				VendorIDs:       entry.VendorIDs,
			}

			if v.Source != (types.DataSource{}) {
				advisory.DataSource = &types.DataSource{
					ID:   v.Source.ID,
					Name: v.Source.Name,
					URL:  v.Source.URL,
				}
			}

			advisories = append(advisories, advisory)
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
			OSVer: osVer,
			Package: Package{
				Name:         ss[0],
				FixedVersion: version.NewVersion(ss[1]).String(),
			},
		})
	}

	for _, c := range cri.Criterias {
		pkgs = walkOracle(c, osVer, pkgs)
	}
	return pkgs
}

func mergeVulnerabilityDetails(detail types.VulnerabilityDetail, oval OracleOVAL, vulnIDs []string) types.VulnerabilityDetail {
	// Collect vulnerability details - references and severity
	// A CVE can be present in multiple ELSAs.  Collect all the applicable references as we process them, later when done we'll insert
	// the references.
	convertedSeverity := severityFromThreat(oval.Severity)

	// If multiple ELSAs for the same CVE have differing severities, use the highest one
	if convertedSeverity > detail.Severity {
		detail.Severity = convertedSeverity
	}

	for _, ref := range oval.References {
		if referencesFromContains(ref.URI, vulnIDs) && !ustrings.InSlice(ref.URI, detail.References) {
			detail.References = append(detail.References, ref.URI)
		}
	}

	return detail
}

func mergeEntries(advisory Advisory, pkg AffectedPackage, elsaID string) Advisory {
	affectedFlavor := GetPackageFlavor(pkg.Package.FixedVersion)

	// Persist the normal flavor package version in FixedVersion for backwards compatibility.
	// Eventually could be removed
	if affectedFlavor == PackageFlavorNormal &&
		version.NewVersion(advisory.FixedVersion).LessThan(version.NewVersion(pkg.Package.FixedVersion)) {
		advisory.FixedVersion = pkg.Package.FixedVersion
	}

	for i, entry := range advisory.Entries {
		entryFlavor := GetPackageFlavor(entry.FixedVersion)

		if entryFlavor == affectedFlavor {
			// This fixed version is newer than the previously found fixed version
			if version.NewVersion(entry.FixedVersion).LessThan(version.NewVersion(pkg.Package.FixedVersion)) {
				advisory.Entries[i].FixedVersion = pkg.Package.FixedVersion
			}

			// Add the ELSA ID to the vendor ID list
			if !ustrings.InSlice(elsaID, entry.VendorIDs) {
				advisory.Entries[i].VendorIDs = append(entry.VendorIDs, elsaID)
			}

			return advisory
		}
	}

	entry := Entry{
		FixedVersion: pkg.Package.FixedVersion,
		VendorIDs:    []string{elsaID},
	}
	advisory.Entries = append(advisory.Entries, entry)

	return advisory
}

func referencesFromContains(source string, matches []string) bool {
	for _, m := range matches {
		if strings.Contains(source, m) {
			return true
		}
	}
	return false
}

// GetPackageFlavor Determine the package "flavor" based on its version string
//   - normal
//   - FIPS validated
//   - ksplice userspace
func GetPackageFlavor(version string) PackageFlavor {
	version = strings.ToLower(version)
	if strings.HasSuffix(version, "_fips") {
		return PackageFlavorFips
	} else {
		subs := strings.Split(version, ".")
		for _, s := range subs {
			if strings.HasPrefix(s, "ksplice") {
				return PackageFlavorKsplice
			}
		}
		return PackageFlavorNormal
	}
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
