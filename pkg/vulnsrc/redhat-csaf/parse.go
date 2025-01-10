package redhatcsaf

import (
	"encoding/json"
	"fmt"
	"iter"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"github.com/samber/oops"
	"go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
)

/*
Temp BoltDB Schema for Raw Entries:

root
└── <module>::<package_name>         // e.g. "httpd:2.4::httpd"
    ├── <vulnerability_id1>          // e.g. "RHSA-2020:4751"
    │   └── value: [                 // JSON array of RawEntry
    │       {
    │           "FixedVersion": "0:2.4.37-30.module+el8.3.0+7001+0766b9e7",
    │           "Status": "fixed",
    │           "Severity": "low",
    │           "Arch": "x86_64",
    │           "CPE": "cpe:/a:redhat:enterprise_linux:8::appstream",
    │           "Alias": "CVE-2018-17189"
    │       },
    │       ...
    │   ]
    └── <vulnerability_id2>
        └── value: [...]
*/

// Fixed path for temporary BoltDB file
// This file will be automatically removed when Clean() is called
const dbPath = "redhat-csaf.db"

// Parser represents a CSAF VEX parser.
type Parser struct {
	repoToCPE map[string][]string
	nvrToCPE  map[string]string
	cpeSet    OrderedSet[string]

	// Due to the large size of CSAF VEX data, we use a temporary BoltDB file
	// to store advisory data instead of keeping everything in memory.
	// This temporary database will be automatically cleaned up when parsing is complete.
	db *bbolt.DB
}

// NewParser creates a new Parser instance.
// If a database file already exists at the fixed path,
// it will be loaded to resume a previous parsing session.
func NewParser() Parser {
	return Parser{
		repoToCPE: map[string][]string{},
		nvrToCPE:  map[string]string{},
		cpeSet:    NewOrderedSet[string](),
	}
}

func (p *Parser) Parse(dir string) error {
	eb := oops.With("dir", dir)

	// Open BoltDB
	var err error
	p.db, err = bbolt.Open(dbPath, 0600, nil)
	if err != nil {
		return eb.With("db_path", dbPath).Wrapf(err, "database open error")
	}

	err = p.db.Batch(func(tx *bbolt.Tx) error {
		if err := p.parse(tx, dir); err != nil {
			return eb.Wrap(err)
		}
		return nil
	})
	if err != nil {
		return eb.Wrap(err)
	}
	return nil
}

func (p *Parser) parse(tx *bbolt.Tx, dir string) error {
	//if err := p.parseRepositoryCPEMapping(dir); err != nil {
	//	return eb.Tags("parse_repo_to_cpe").Wrap(err)
	//}
	if err := p.parseCSAF(tx, dir); err != nil {
		return oops.Tags("parse_csaf").Wrap(err)
	}
	return nil
}

func (p *Parser) parseCSAF(tx *bbolt.Tx, dir string) error {
	rootDir := filepath.Join(dir, vulnListDir, csafDir)
	eb := oops.Tags("parse_csaf_vex").With("root", rootDir)

	// Collect all JSON files for the progress bar
	filePaths, err := p.collectFilePaths(rootDir)
	if err != nil {
		return eb.Wrap(err)
	}

	bar := utils.NewProgressBar(len(filePaths))
	defer bar.Finish()

	for _, filePath := range filePaths {
		if err := p.parseCSAFFile(tx, filePath); err != nil {
			return eb.Wrap(err)
		}
		bar.Increment()
	}
	return nil
}

func (p *Parser) parseCSAFFile(tx *bbolt.Tx, filePath string) error {
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

	if err = p.parseAdvisory(tx, adv); err != nil {
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
		// TODO(debug): delete
		//if filepath.Base(path) != "cve-2023-39325.json" {
		//	return nil
		//}
		filePaths = append(filePaths, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return filePaths, nil
}

func (p *Parser) parseRepositoryCPEMapping(dir string) error {
	filePath := filepath.Join(dir, vulnListDir, cpeDir, "repository-to-cpe.json")
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

func (p *Parser) parseAdvisory(tx *bbolt.Tx, adv CSAFAdvisory) error {
	// Process vulnerabilities
	if len(adv.Vulnerabilities) != 1 {
		return oops.With("number", len(adv.Vulnerabilities)).Errorf("invalid number of vulnerabilities")
	}

	if err := p.parseVulnerability(tx, adv, adv.Vulnerabilities[0]); err != nil {
		return oops.Wrapf(err, "failed to parse vulnerability")
	}

	return nil
}

// parseVulnerability retrieves CSAF VEX data for a specific vulnerability,
// extracts raw per-package entries, and then converts them into advisories.
func (p *Parser) parseVulnerability(tx *bbolt.Tx, adv CSAFAdvisory, vuln *csaf.Vulnerability) error {
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
			if *productID == "red_hat_satellite_6:yggdrasil" {
				fmt.Println(*productID, *remediation.Category, status.String())
			}
			product, err := adv.LookUpProduct(*productID)
			if err != nil {
				return eb.Wrap(err)
			} else if product == nil {
				continue
			} else if product.Package.Type != packageurl.TypeRPM {
				// OCI images are not supported
				// e.g.
				//    Product: CERT-MANAGER-1.11-RHEL-9
				//    Component: cert-manager/cert-manager-operator-rhel9
				// cf. https://access.redhat.com/security/cve/CVE-2023-39325
				continue
			}

			arch := product.Package.Qualifiers.Map()["arch"]
			if arch == "src" {
				// If arch is "src", treat it as empty.
				// This is applicable only with unfixed vulnerabilities (as far as we know).
				arch = ""
			}

			pkgName := product.Package.Name
			if product.Package.Namespace != "" {
				// Some PURLs have a namespace, which is unclear how to handle.
				// cf. https://issues.redhat.com/browse/SECDATA-854
				pkgName = product.Package.Namespace + "/" + pkgName
			}

			pkg := Package{
				Module: product.Module,
				Name:   pkgName,
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

			p.addRawEntry(tx, pkg, vulnID, rawEntry)
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
		// If the advisory has a fixed version, it is considered as fixed.
		// To keep the database size small, we don't store the "fixed" status.
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
		switch lo.FromPtr(threat.Category) {
		case csaf.CSAFThreatCategoryImpact:
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

// addRawEntry stores a raw entry in the temporary BoltDB file.
// The entry is stored under <module>::<package_name> bucket with
// vulnerability_id as key and JSON array of RawEntries as value.
func (p *Parser) addRawEntry(tx *bbolt.Tx, pkg Package, vulnID VulnerabilityID, entry RawEntry) error {
	eb := oops.With("module", pkg.Module).With("package", pkg.Name).With("vuln_id", vulnID)

	// Create package bucket key
	pkgKey := []byte(pkg.Module + "::" + pkg.Name)
	eb.With("pkg_key", string(pkgKey))

	// Get or create package bucket
	pkgBucket, err := tx.CreateBucketIfNotExists(pkgKey)
	if err != nil {
		return eb.Wrapf(err, "failed to create package bucket")
	}

	// Get existing entries
	var entries RawEntries
	if data := pkgBucket.Get([]byte(vulnID)); data != nil {
		if err := json.Unmarshal(data, &entries); err != nil {
			return oops.Wrapf(err, "failed to unmarshal entries")
		}
	}

	// Append new entry and store
	entries = append(entries, entry)
	data, err := json.Marshal(entries)
	if err != nil {
		return oops.Wrapf(err, "failed to marshal entries")
	}

	if err := pkgBucket.Put([]byte(vulnID), data); err != nil {
		return oops.Wrapf(err, "failed to put entries")
	}

	return nil
}

// Advisories returns a sequence of advisories stored in the temporary database.
// This method reads from nested buckets in BoltDB instead of memory to handle
// large datasets efficiently.
func (p *Parser) Advisories() iter.Seq2[Bucket, RawEntries] {
	eb := oops.Tags("boltdb", "advisories")
	return func(yield func(Bucket, RawEntries) bool) {
		if err := p.db.View(func(tx *bbolt.Tx) error {
			// Iterate through package buckets
			return tx.ForEach(func(pkgKey []byte, pkgBucket *bbolt.Bucket) error {
				if pkgBucket == nil {
					return nil
				}
				eb = eb.Tags("boltdb").With("pkg_key", string(pkgKey))

				// Split package key into module and name
				var module, name string
				before, after, ok := strings.Cut(string(pkgKey), "::")
				if ok {
					module, name = before, after
				} else {
					name = before
				}
				pkg := Package{
					Module: module,
					Name:   name,
				}
				eb = eb.With("module", module).With("package", name)

				// Iterate through vulnerability entries
				return pkgBucket.ForEach(func(vulnKey, data []byte) error {
					if data == nil {
						return nil
					}
					eb = eb.With("vuln_id", string(vulnKey))

					var entries RawEntries
					if err := json.Unmarshal(data, &entries); err != nil {
						return eb.Wrapf(err, "failed to unmarshal entries")
					}

					bkt := Bucket{
						Package:         pkg,
						VulnerabilityID: VulnerabilityID(vulnKey),
					}
					if !yield(bkt, entries) {
						return nil
					}
					return nil
				})
			})
		}); err != nil {
			log.Printf("failed to iterate through package buckets: %v", eb.Wrap(err))
		}
	}
}

// AdvisoryNum returns the total number of advisories stored in the database
func (p *Parser) AdvisoryNum() int {
	var count int
	for range p.Advisories() {
		count++
	}
	return count
}

// Clean closes the database connection and removes the temporary database file.
// Comment out this method when debugging to preserve the database file.
func (p *Parser) Clean() error {
	if err := p.db.Close(); err != nil {
		return oops.Wrapf(err, "failed to close database")
	}

	if err := os.Remove(dbPath); err != nil {
		return oops.Wrapf(err, "failed to remove database file")
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
