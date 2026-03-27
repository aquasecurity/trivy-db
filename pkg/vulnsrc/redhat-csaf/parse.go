package redhatcsaf

import (
	"encoding/gob"
	"encoding/json"
	"iter"
	"maps"
	"os"
	"slices"
	"path"
	"path/filepath"
	"strings"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"github.com/samber/oops"

	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/set"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	redhatoval "github.com/aquasecurity/trivy-db/pkg/vulnsrc/redhat-oval"
)

// Fixed path for temporary data file
// This file will be automatically removed when Clean() is called
const dataPath = "redhat-csaf.data"

type Parser struct {
	vulnListDir string
	csafDir     string
	cpeDir      string
	repoToCPE   map[string][]string
	nvrToCPE    map[string][]string
	advisories  map[Package]map[VulnerabilityID]RawEntries
	cpeSet      set.Ordered[string]
}

func NewParser(vulnListDir, csafDir, cpeDir string) Parser {
	// Register types for gob encoding
	gob.Register(Package{})
	gob.Register(VulnerabilityID(""))
	gob.Register(RawEntry{})
	gob.Register(RawEntries{})
	gob.Register(csaf.CPE(""))

	return Parser{
		vulnListDir: vulnListDir,
		csafDir:     csafDir,
		cpeDir:      cpeDir,
		repoToCPE:   map[string][]string{},
		nvrToCPE:    map[string][]string{},
		advisories:  map[Package]map[VulnerabilityID]RawEntries{},
		cpeSet:      set.NewOrdered[string](),
	}
}

func (p *Parser) Parse(dir string) error {
	// Load advisories from the cache for debugging
	if err := p.loadAdvisories(); err == nil {
		log.Info("Loaded CSAF VEX data from the cache")
		return nil
	}

	vulnListDir := filepath.Join(dir, p.vulnListDir)
	eb := oops.With("dir", vulnListDir)

	if p.cpeDir != "" {
		if err := p.parseRepositoryCPEMapping(vulnListDir); err != nil {
			return eb.Wrap(err)
		}
		if err := p.parseNVRCPEMapping(vulnListDir); err != nil {
			return eb.Wrap(err)
		}
	}

	if err := p.parseCSAF(vulnListDir); err != nil {
		return eb.Wrap(err)
	}

	// Serialization after all files are processed
	if err := p.serializeAdvisories(); err != nil {
		return eb.Wrap(err)
	}
	return nil
}

func (p *Parser) parseCSAF(dir string) error {
	rootDir := filepath.Join(dir, p.csafDir)
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

	var raw csaf.Advisory
	if err := json.NewDecoder(f).Decode(&raw); err != nil {
		return eb.Wrapf(err, "JSON decode error")
	}
	adv := NewCSAFAdvisory(raw)

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
	filePath := filepath.Join(dir, p.cpeDir, "repository-to-cpe.json")
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
	filePath := filepath.Join(dir, p.cpeDir, "nvr-to-cpe.json")
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
		uniq := set.New[uniqKey]()

		// Separate source and binary products. Binary packages are preferred,
		// but when only source packages exist (as with some VEX feeds), the
		// source package is used as a fallback so the advisory is still stored.
		type resolvedProduct struct {
			productID csaf.ProductID
			product   *Product
		}
		var binaryProducts, srcProducts []resolvedProduct
		for _, productID := range lo.FromPtr(remediation.ProductIds) {
			if productID == nil {
				continue
			}
			product := adv.LookUpProduct(*productID)
			if product == nil {
				continue
			}
			if product.Package.Type != packageurl.TypeRPM {
				continue
			}

			// Add CPEs to the set
			p.cpeSet.Append(string(product.Stream))

			// When no external CPE mapping files are provided, extract
			// repository-to-CPE mappings from PURL qualifiers.
			if p.cpeDir == "" && product.Stream != "" {
				qualifiers := product.Package.Qualifiers.Map()
				repoID := qualifiers["repository_id"]
				if repoID == "" {
					repoID = qualifiers["repository_url"]
				}
				if repoID != "" {
					existing := p.repoToCPE[repoID]
					if !slices.Contains(existing, string(product.Stream)) {
						p.repoToCPE[repoID] = append(existing, string(product.Stream))
					}
				}
			}

			arch := product.Package.Qualifiers.Map()["arch"]
			if arch == "src" || arch == "source" {
				srcProducts = append(srcProducts, resolvedProduct{*productID, product})
			} else {
				binaryProducts = append(binaryProducts, resolvedProduct{*productID, product})
			}
		}

		// Use binary products when available. For source packages, include
		// them only when no binary package with the same name exists in this
		// remediation. This handles feeds where some products (e.g., Hummingbird)
		// only have source RPM references while others (e.g., RHEL) have binary
		// RPM references in the same remediation.
		binaryNames := set.New[string]()
		for _, rp := range binaryProducts {
			binaryNames.Append(rp.product.Package.Name)
		}
		products := binaryProducts
		for _, rp := range srcProducts {
			if !binaryNames.Contains(rp.product.Package.Name) {
				products = append(products, rp)
			}
		}

		for _, rp := range products {
			product := rp.product
			arch := product.Package.Qualifiers.Map()["arch"]

			// Clear arch for source packages used as fallback so they
			// match any architecture at scan time.
			if arch == "src" || arch == "source" {
				arch = ""
			}

			// Log unexpected case: unpatched vulnerability with arch specified
			if status != types.StatusFixed && arch != "" {
				log.Warn("Unexpected arch for unpatched vulnerability",
					log.String("arch", arch),
					log.String("cve_id", string(cveID)),
					log.String("package", product.Package.Name))
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
				Severity:     severities[rp.productID],
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

func (p *Parser) CPEList() redhatoval.CPEList {
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
