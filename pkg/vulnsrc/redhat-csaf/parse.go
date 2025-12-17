package redhatcsaf

import (
	"encoding/gob"
	"encoding/json"
	"iter"
	"log"
	"maps"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"github.com/samber/oops"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
)

// Fixed path for temporary data file
// This file will be automatically removed when Clean() is called
const dataPath = "redhat-csaf.data"

type Parser struct {
	repoToCPE  map[string][]string
	nvrToCPE   map[string][]string
	advisories map[Package]map[VulnerabilityID]RawEntries
	cpeSet     OrderedSet[string]
}

func NewParser() Parser {
	// Register types for gob encoding
	gob.Register(Package{})
	gob.Register(VulnerabilityID(""))
	gob.Register(RawEntry{})
	gob.Register(RawEntries{})
	gob.Register(csaf.CPE(""))

	return Parser{
		repoToCPE:  map[string][]string{},
		nvrToCPE:   map[string][]string{},
		advisories: map[Package]map[VulnerabilityID]RawEntries{},
		cpeSet:     NewOrderedSet[string](),
	}
}

func (p *Parser) Parse(dir string) error {
	// Load advisories from the cache for debugging
	if err := p.loadAdvisories(); err == nil {
		log.Println("Loaded CSAF VEX data from the cache")
		return nil
	}

	eb := oops.With("dir", dir)
	if err := p.parseRepositoryCPEMapping(dir); err != nil {
		return eb.Wrap(err)
	}
	if err := p.parseNVRCPEMapping(dir); err != nil {
		return eb.Wrap(err)
	}
	if err := p.parseCSAF(dir); err != nil {
		return eb.Wrap(err)
	}

	// Serialization after all files are processed
	if err := p.serializeAdvisories(); err != nil {
		return eb.Wrap(err)
	}
	return nil
}

func (p *Parser) parseCSAF(dir string) error {
	rootDir := filepath.Join(dir, csafDir)
	eb := oops.Tags("parse_csaf_vex").With("root", rootDir)

	// Collect all JSON files for the progress bar
	filePaths, err := p.collectFilePaths(rootDir)
	if err != nil {
		return eb.Wrap(err)
	}

	bar := utils.NewProgressBar(len(filePaths))
	defer bar.Finish()

	for _, filePath := range filePaths {
		if err := p.parseCSAFFile(filePath); err != nil {
			return eb.Wrap(err)
		}
		bar.Increment()
	}
	return nil
}

func (p *Parser) parseCSAFFile(filePath string) error {
	eb := oops.Code("walk_error").With("path", filePath)
	f, err := os.Open(filePath)
	if err != nil {
		return eb.Wrapf(err, "file open error")
	}
	defer f.Close()

	var adv CSAFAdvisory
	if err := json.NewDecoder(f).Decode(&adv); err != nil {
		return eb.Wrapf(err, "JSON decode error")
	}

	if err = p.parseAdvisory(adv); err != nil {
		return eb.Wrapf(err, "advisory parse error")
	}
	return nil
}

func (p *Parser) collectFilePaths(rootDir string) ([]string, error) {
	var filePaths []string
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		eb := oops.Code("walk_error").With("path", path)
		if err != nil {
			return eb.Wrapf(err, "walk error")
		} else if info.IsDir() || filepath.Ext(info.Name()) != ".json" {
			return nil
		}
		filePaths = append(filePaths, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return filePaths, nil
}

func (p *Parser) parseRepositoryCPEMapping(dir string) error {
	filePath := filepath.Join(dir, cpeDir, "repository-to-cpe.json")
	eb := oops.Tags("repository-to-cpe").With("path", filePath)

	f, err := os.Open(filePath)
	if err != nil {
		return eb.Wrap(err)
	}
	defer f.Close()

	if err = json.NewDecoder(f).Decode(&p.repoToCPE); err != nil {
		return eb.Code("json_decode_error").Wrap(err)
	}

	for _, cpes := range p.repoToCPE {
		cpes = lo.Map(cpes, func(cpe string, _ int) string { return strings.TrimSpace(cpe) })
		p.cpeSet.Append(cpes...)
	}

	return nil
}

func (p *Parser) parseNVRCPEMapping(dir string) error {
	filePath := filepath.Join(dir, cpeDir, "nvr-to-cpe.json")
	eb := oops.Tags("nvr-to-cpe").With("path", filePath)

	f, err := os.Open(filePath)
	if err != nil {
		return eb.Wrapf(err, "file open error")
	}
	defer f.Close()

	if err = json.NewDecoder(f).Decode(&p.nvrToCPE); err != nil {
		return eb.Wrapf(err, "JSON parse error")
	}

	for _, cpes := range p.nvrToCPE {
		p.cpeSet.Append(cpes...)
	}
	return nil
}

func (p *Parser) parseAdvisory(adv CSAFAdvisory) error {
	// Process vulnerabilities
	if len(adv.Vulnerabilities) != 1 {
		return oops.With("number", len(adv.Vulnerabilities)).Errorf("invalid number of vulnerabilities")
	}

	if err := p.parseVulnerability(adv, adv.Vulnerabilities[0]); err != nil {
		return oops.Wrapf(err, "failed to parse vulnerability")
	}

	return nil
}

// parseVulnerability retrieves CSAF VEX data for a specific vulnerability,
// extracts raw per-package entries, and then converts them into advisories.
func (p *Parser) parseVulnerability(adv CSAFAdvisory, vuln *csaf.Vulnerability) error {
	if vuln == nil {
		return nil
	}

	// Extract severities from Threats
	severities := p.parseThreats(vuln.Threats)

	cveID := VulnerabilityID(lo.FromPtr(vuln.CVE))
	if cveID == "" {
		return oops.Errorf("empty CVE ID")
	}
	eb := oops.With("cve_id", cveID)

	// Process remediations
	// cf. https://redhatproductsecurity.github.io/security-data-guidelines/csaf-vex/#remediations
	for _, remediation := range vuln.Remediations {
		if remediation == nil {
			continue
		}

		status := p.detectStatus(remediation)
		if status == types.StatusUnknown {
			continue
		}
		eb = eb.With("status", status)

		// Note on CPE deduplication:
		// Different product_ids within a single remediation may resolve to identical pairs of PURLs and CPEs.
		// In such cases, we need to eliminate duplicate records to avoid redundancy.
		//
		// For example:
		// - Product ID: 6Server-RHSCL-2.0-6.5.Z:rh-mariadb100-mariadb-1:10.0.20-1.el6.src
		//    -> PURL: pkg:rpm/redhat/rh-mariadb100-mariadb@10.0.20-1.el6?arch=src\u0026epoch=1
		//       CPE: cpe:/a:redhat:rhel_software_collections:2::el6
		// - Product ID: 6Workstation-RHSCL-2.0:rh-mariadb100-mariadb-1:10.0.20-1.el6.src
		//    -> PURL: pkg:rpm/redhat/rh-mariadb100-mariadb@10.0.20-1.el6?arch=src\u0026epoch=1
		//       CPE: cpe:/a:redhat:rhel_software_collections:2::el6
		//
		// In this case, we only need to keep one record since they represent the same affected component.
		type uniqKey struct {
			Package
			RawEntry
		}
		uniq := NewSet[uniqKey]()

		// For each remediation, iterate over product_ids
		for _, productID := range lo.FromPtr(remediation.ProductIds) {
			if productID == nil {
				continue
			}
			product, err := adv.LookUpProduct(*productID)
			if err != nil {
				return eb.Wrap(err)
			}
			if product == nil {
				continue
			}
			if product.Package.Type != packageurl.TypeRPM {
				// OCI images are not supported
				// e.g.
				//    Product: CERT-MANAGER-1.11-RHEL-9
				//    Component: cert-manager/cert-manager-operator-rhel9
				// cf. https://access.redhat.com/security/cve/CVE-2023-39325
				continue
			}

			// Add CPEs to the set
			p.cpeSet.Append(string(product.Stream))

			// PURL format differs between patched and unpatched vulnerabilities:
			//
			// Patched (vendor_fix):
			//   - Binary packages have version and arch: pkg:rpm/redhat/pam@1.5.1-21.el9_5?arch=x86_64
			//   - Source packages have version and arch=src: pkg:rpm/redhat/pam@1.5.1-21.el9_5?arch=src
			//
			// Unpatched (none_available: "Affected"/"Fix deferred", no_fix_planned: "Out of support scope"/"Will not fix"):
			//   - Binary packages have NO version and NO arch: pkg:rpm/redhat/vim-X11
			//   - Source packages have arch=src only: pkg:rpm/redhat/vim?arch=src
			//
			// cf. https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-10041.json (patched)
			// cf. https://security.access.redhat.com/data/csaf/v2/vex/2023/cve-2023-5344.json (unpatched)
			arch := product.Package.Qualifiers.Map()["arch"]
			if arch == "src" {
				// Skip source packages to maintain backward compatibility with OVALv2,
				// which only included binary package names.
				// Now that SECDATA-1097 has been resolved, binary package names are also
				// included for unpatched vulnerabilities, so we can safely skip source packages.
				// cf. https://issues.redhat.com/browse/SECDATA-1097
				//
				// TODO(v3): In Trivy DB v3, consider storing only source package names instead
				// of binary package names for better storage efficiency, as one source package
				// typically produces multiple binary packages.
				continue
			}

			// Log unexpected case: unpatched vulnerability with arch specified
			// Based on investigation, unpatched binary packages should not have arch in PURL.
			// If this happens, it may indicate a format change that needs attention.
			if status != types.StatusFixed && arch != "" {
				log.Printf("WARN: unexpected arch %q for unpatched vulnerability %s, package %s",
					arch, cveID, product.Package.Name)
			}

			pkg := Package{
				Module: product.Module,
				Name:   product.Package.Name,
			}

			var vulnID, alias VulnerabilityID
			if status == types.StatusFixed {
				vulnID = p.extractRHSAID(remediation)
				alias = cveID
			} else {
				vulnID = cveID
			}

			fixedVersion := product.Package.Version
			if epoch, ok := product.Package.Qualifiers.Map()["epoch"]; ok {
				fixedVersion = epoch + ":" + fixedVersion
			}

			rawEntry := RawEntry{
				FixedVersion: fixedVersion,
				Severity:     severities[*productID],
				Arch:         arch,
				CPE:          product.Stream,
				Alias:        alias,

				// If the package has a non-empty FixedVersion, we omit the status
				// to reduce DB size, because it's obviously "fixed".
				Status: lo.Ternary(product.Package.Version == "", status, 0),
			}

			// Deduplicate raw entries
			key := uniqKey{
				Package:  pkg,
				RawEntry: rawEntry,
			}
			if uniq.Contains(key) {
				continue
			}
			uniq.Append(key)

			p.addRawEntry(pkg, vulnID, rawEntry)
		}
	}
	return nil
}

func (p *Parser) detectStatus(remediation *csaf.Remediation) types.Status {
	switch lo.FromPtr(remediation.Category) {
	case csaf.CSAFRemediationCategoryNoFixPlanned:
		if lo.FromPtr(remediation.Details) == "Out of support scope" {
			return types.StatusEndOfLife
		} else if lo.FromPtr(remediation.Details) == "Will not fix" {
			return types.StatusWillNotFix
		}
	case csaf.CSAFRemediationCategoryNoneAvailable:
		if lo.FromPtr(remediation.Details) == "Affected" {
			return types.StatusAffected
		} else if lo.FromPtr(remediation.Details) == "Deferred" {
			return types.StatusFixDeferred
		}
	case csaf.CSAFRemediationCategoryVendorFix:
		return types.StatusFixed
	}
	return types.StatusUnknown
}

func (p *Parser) extractRHSAID(remediation *csaf.Remediation) VulnerabilityID {
	u := lo.FromPtr(remediation.URL)
	_, rhsaID := path.Split(u)
	return VulnerabilityID(rhsaID)
}

// parseThreats extracts severities from "threats" in a CSAF VEX.
// cf. https://redhatproductsecurity.github.io/security-data-guidelines/csaf-vex/#general-cve-information
func (p *Parser) parseThreats(threats csaf.Threats) map[csaf.ProductID]types.Severity {
	severities := map[csaf.ProductID]types.Severity{}
	for _, threat := range threats {
		if threat == nil {
			continue
		}

		var severity types.Severity
		if lo.FromPtr(threat.Category) == csaf.CSAFThreatCategoryImpact {
			severity = convertSeverity(*threat.Details)
		}
		if severity == types.SeverityUnknown {
			continue
		}
		for _, productID := range lo.FromPtr(threat.ProductIds) {
			severities[lo.FromPtr(productID)] = severity
		}
	}
	return severities
}

// addRawEntry stores raw, per-package entries from the CSAF VEX data without further aggregation or processing.
func (p *Parser) addRawEntry(pkg Package, vulnID VulnerabilityID, entry RawEntry) {
	if _, ok := p.advisories[pkg]; !ok {
		p.advisories[pkg] = map[VulnerabilityID]RawEntries{}
	}
	p.advisories[pkg][vulnID] = append(p.advisories[pkg][vulnID], entry)
}

func (p *Parser) Advisories() iter.Seq2[Bucket, RawEntries] {
	return func(yield func(Bucket, RawEntries) bool) {
		for pkg, vulns := range p.advisories {
			for vulnID, entries := range vulns {
				if !yield(Bucket{
					Package:         pkg,
					VulnerabilityID: vulnID,
				}, entries) {
					return
				}
			}
		}
	}
}

func (p *Parser) AdvisoryNum() int {
	var count int
	for _, vulns := range p.advisories {
		count += len(vulns)
	}
	return count
}

func (p *Parser) CPEList() CPEList {
	return p.cpeSet.Values()
}

func (p *Parser) RepoToCPE() iter.Seq2[string, []string] {
	return maps.All(p.repoToCPE)
}

func (p *Parser) NVRToCPE() iter.Seq2[string, []string] {
	return maps.All(p.nvrToCPE)
}

// SerializeAdvisories saves the current advisories map to a file
func (p *Parser) serializeAdvisories() error {
	if os.Getenv("TRIVY_REDHAT_CSAF_VEX_DEBUG") == "" {
		return nil
	}
	// Open file for writing
	f, err := os.Create(dataPath)
	if err != nil {
		return oops.Wrapf(err, "failed to create file")
	}
	defer f.Close()

	// Encode map to file using gob
	enc := gob.NewEncoder(f)
	if err = enc.Encode(p.advisories); err != nil {
		return oops.Wrapf(err, "failed to encode data")
	}

	return nil
}

// loadAdvisories loads the advisories map from a file
func (p *Parser) loadAdvisories() error {
	if os.Getenv("TRIVY_REDHAT_CSAF_VEX_DEBUG") == "" {
		return oops.Errorf("debug mode is disabled")
	}

	// Open file for reading
	f, err := os.Open(dataPath)
	if err != nil {
		return oops.Wrapf(err, "failed to open file")
	}
	defer f.Close()

	// Decode map from file using gob
	dec := gob.NewDecoder(f)
	if err = dec.Decode(&p.advisories); err != nil {
		return oops.Wrapf(err, "failed to decode data")
	}

	return nil
}

func convertSeverity(impact string) types.Severity {
	switch strings.ToLower(impact) {
	case "low":
		return types.SeverityLow
	case "moderate":
		return types.SeverityMedium
	case "important":
		return types.SeverityHigh
	case "critical":
		return types.SeverityCritical
	default:
		return types.SeverityUnknown
	}
}
