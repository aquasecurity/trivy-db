package debian

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	version "github.com/knqyf263/go-deb-version"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	debianDir = "debian"

	// Type
	packageType = "package"
	xrefType    = "xref"

	// File or directory to parse
	distributionsFile = "distributions.json"
	sourcesDir        = "source"
	updateSourcesDir  = "updates-source"
	cveDir            = "CVE"
	dlaDir            = "DLA"
	dsaDir            = "DSA"

	// This bucket stores unfixed vulnerabilities only.
	// e.g. debian 8
	platformFormat = "debian %s"

	// The security advisories are not from OVAL, but we have to keep this bucket for backward compatibility.
	// This bucket stores fixed vulnerabilities only.
	// e.g. debian oval 8
	ovalPlatformFormat = "debian oval %s"
)

var (
	// NOTE: "removed" should not be marked as "not-affected".
	// ref. https://security-team.debian.org/security_tracker.html#removed-packages
	skipStatuses = []string{"not-affected", "undetermined"}
)

type VulnSrc struct {
	dbc db.Operation

	// Hold a map of codenames and major versions from distributions.json
	// e.g. "buster" => "10"
	distributions map[string]string

	// Hold the latest versions of each codename in Sources.json
	// e.g. {"buster", "bash"} => "5.0-4"
	pkgVersions map[bucket]string

	// Hold the fixed versions of vulnerabilities in sid
	// e.g. {"putty", "CVE-2021-36367"} => "0.75-3" // fixed vulnerability
	//      {"ndpi",  "CVE-2021-36082"} => ""       // unfixed vulnerability
	sidFixedVersions map[bucket]string

	// Hold debian advisories
	// e.g. {"buster", "connman", "CVE-2021-33833"} => {"FixedVersion": 1.36-2.1~deb10u2, ...}
	bktAdvisories map[bucket]types.Advisory

	// Hold not-affected versions
	// e.g. {"buster", "linux", "CVE-2021-3739"} => {}
	notAffected map[bucket]struct{}
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc:              db.Config{},
		distributions:    map[string]string{},
		pkgVersions:      map[bucket]string{},
		sidFixedVersions: map[bucket]string{},
		bktAdvisories:    map[bucket]types.Advisory{},
		notAffected:      map[bucket]struct{}{},
	}
}

func (vs VulnSrc) Name() string {
	return vulnerability.Debian
}

func (vs VulnSrc) Update(dir string) error {
	if err := vs.parse(dir); err != nil {
		return xerrors.Errorf("parse error: %w", err)
	}

	if err := vs.save(); err != nil {
		return xerrors.Errorf("save error: %w", err)
	}

	return nil
}

func (vs VulnSrc) parse(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", debianDir)

	// Parse distributions.json
	if err := vs.parseDistributions(rootDir); err != nil {
		return xerrors.Errorf("distributions error: %w", err)
	}

	// Parse source/**.json
	if err := vs.parseSources(filepath.Join(rootDir, sourcesDir)); err != nil {
		return xerrors.Errorf("source parse error: %w", err)
	}

	// Parse updates-source/**.json
	if err := vs.parseSources(filepath.Join(rootDir, updateSourcesDir)); err != nil {
		return xerrors.Errorf("updates-source parse error: %w", err)
	}

	// Parse CVE/*.json
	if err := vs.parseCVE(rootDir); err != nil {
		return xerrors.Errorf("CVE error: %w", err)
	}

	// Parse DLA/*.json
	if err := vs.parseDLA(rootDir); err != nil {
		return xerrors.Errorf("DLA error: %w", err)
	}

	// Parse DSA/*.json
	if err := vs.parseDSA(rootDir); err != nil {
		return xerrors.Errorf("DSA error: %w", err)
	}

	return nil
}

func (vs VulnSrc) parseBug(dir string, fn func(Bug) error) error {
	err := utils.FileWalk(dir, func(r io.Reader, path string) error {
		var bug Bug
		if err := json.NewDecoder(r).Decode(&bug); err != nil {
			return xerrors.Errorf("json decode error: %w", err)
		}

		if err := fn(bug); err != nil {
			return xerrors.Errorf("parse debian bug error: %w", err)
		}
		return nil
	})

	if err != nil {
		return xerrors.Errorf("walk error: %w", err)
	}
	return nil
}

func (vs VulnSrc) parseCVE(dir string) error {
	log.Println("  Parsing CVE JSON files...")
	err := vs.parseBug(filepath.Join(dir, cveDir), func(bug Bug) error {
		// Hold severities per the packages
		severities := map[string]types.Severity{}
		cveID := bug.Header.ID

		for _, ann := range bug.Annotations {
			if ann.Type != packageType {
				continue
			}

			bkt := bucket{
				codeName: ann.Release, // It will be empty in the case of sid.
				pkgName:  ann.Package,
				vulnID:   cveID,
			}

			// Skip not-affected, removed or undetermined advisories
			if utils.StringInSlice(ann.Kind, skipStatuses) {
				vs.notAffected[bkt] = struct{}{}
				continue
			}

			// For sid
			if ann.Release == "" {
				sidBkt := bucket{
					pkgName: ann.Package,
					vulnID:  cveID,
				}
				if ann.Severity != "" {
					severity := severityFromUrgency(ann.Severity)
					severities[ann.Package] = severity
					sidBkt.severity = severity
				}

				vs.sidFixedVersions[sidBkt] = ann.Version // it may be empty for unfixed vulnerabilities

				continue
			}

			advisory := types.Advisory{
				FixedVersion: ann.Version, // It might be empty because of no-dsa.
				Severity:     severities[ann.Package],
			}

			if ann.Version == "" {
				// Populate State only when FixedVersion is empty.
				// e.g. no-dsa
				advisory.State = ann.Kind
			}

			// This advisory might be overwritten by DLA/DSA.
			vs.bktAdvisories[bkt] = advisory
		}

		return nil
	})
	if err != nil {
		return xerrors.Errorf("CVE parse error: %w", err)
	}
	return nil
}

func (vs VulnSrc) parseDLA(dir string) error {
	log.Println("  Parsing DLA JSON files...")
	if err := vs.parseAdvisory(filepath.Join(dir, dlaDir)); err != nil {
		return xerrors.Errorf("DLA parse error: %w", err)
	}
	return nil
}

func (vs VulnSrc) parseDSA(dir string) error {
	log.Println("  Parsing DSA JSON files...")
	if err := vs.parseAdvisory(filepath.Join(dir, dsaDir)); err != nil {
		return xerrors.Errorf("DSA parse error: %w", err)
	}
	return nil
}

func (vs VulnSrc) parseAdvisory(dir string) error {
	return vs.parseBug(dir, func(bug Bug) error {
		var cveIDs []string
		advisoryID := bug.Header.ID
		for _, ann := range bug.Annotations {
			// DLA/DSA is associated with CVE-IDs
			// e.g. "DSA-4931-1" => "{CVE-2021-0089 CVE-2021-26313 CVE-2021-28690 CVE-2021-28692}"
			if ann.Type == xrefType {
				cveIDs = ann.Bugs
				continue
			} else if ann.Type != packageType {
				continue
			}

			// Some advisories don't have any CVE-IDs
			// e.g. https://security-tracker.debian.org/tracker/DSA-3714-1
			vulnIDs := cveIDs
			if len(vulnIDs) == 0 {
				// Use DLA-ID or DSA-ID instead of CVE-ID
				vulnIDs = []string{advisoryID}
			}

			for _, vulnID := range vulnIDs {
				bkt := bucket{
					codeName: ann.Release,
					pkgName:  ann.Package,
					vulnID:   vulnID,
				}

				// Skip not-affected, removed or undetermined advisories
				if utils.StringInSlice(ann.Kind, skipStatuses) {
					vs.notAffected[bkt] = struct{}{}
					continue
				}

				adv, ok := vs.bktAdvisories[bkt]
				if ok {
					// If some advisories fix the same CVE-ID, the latest version will be taken.
					// We assume that the first fix was insufficient and the next advisory fixed it correctly.
					res, err := compareVersions(ann.Version, adv.FixedVersion)
					if err != nil {
						return xerrors.Errorf("version error %s: %w", advisoryID, err)
					}

					// Replace the fixed version with the newer version.
					if res > 0 {
						adv.FixedVersion = ann.Version
						adv.State = "" // State should be empty because this advisory has fixed version actually.
					}
					adv.VendorIDs = append(adv.VendorIDs, advisoryID)
				} else {
					adv = types.Advisory{
						FixedVersion: ann.Version,
						VendorIDs:    []string{advisoryID},
					}
				}

				vs.bktAdvisories[bkt] = adv
			}
		}

		return nil
	})
}

func (vs VulnSrc) save() error {
	log.Println("Saving Debian DB")
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx)
	})
	if err != nil {
		return xerrors.Errorf("batch update error: %w", err)
	}
	log.Println("Saved Debian DB")
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx) error {
	// Iterate all pairs of package name and CVE-ID in sid
	for sidBkt, sidVer := range vs.sidFixedVersions {
		pkgName := sidBkt.pkgName
		cveID := sidBkt.vulnID

		// Skip if the advisory is stated as "not-affected" for all distributions.
		if _, ok := vs.notAffected[bucket{pkgName: pkgName, vulnID: cveID}]; ok {
			continue
		}

		// Iterate all codenames, e.g. buster
		for code := range vs.distributions {
			bkt := bucket{
				codeName: code,
				pkgName:  pkgName,
				vulnID:   cveID,
			}

			// Skip if the advisory is stated as "not-affected" for the specific distribution.
			if _, ok := vs.notAffected[bkt]; ok {
				continue
			}

			// Check if the advisory already exists for the codename
			// If yes, it will be inserted into DB later.
			adv, ok := vs.bktAdvisories[bkt]
			if ok && adv.State == "" {
				// "no-dsa" or "postponed" might be wrong, and it may have a fixed version.
				// e.g.
				//  - https://security-tracker.debian.org/tracker/CVE-2020-8631 (buster no-dsa is wrong)
				//  - https://security-tracker.debian.org/tracker/CVE-2020-25670 (bullseye postponed is wrong)
				continue
			}

			// If no, the fixed version needs to be determined by comparing with the fixed version in sid.
			pkgBkt := bucket{
				codeName: code,
				pkgName:  pkgName,
			}

			// Get the latest version in the release
			// e.g. {"buster", "bash"} => "5.0-4"
			codeVer, ok := vs.pkgVersions[pkgBkt]
			if !ok {
				continue
			}

			// Check if the release has the fixed version
			fixed, err := hasFixedVersion(sidVer, codeVer)
			if err != nil {
				return xerrors.Errorf("version error: %w", err)
			}

			if fixed {
				adv.FixedVersion = sidVer
				adv.State = "" // Overwrite state such as "no-dsa" and "postponed" because it is wrong.
				delete(vs.bktAdvisories, bkt)
			}

			// Add severity
			adv.Severity = sidBkt.severity

			bkt.vulnID = cveID
			if err = vs.put(tx, bkt, adv); err != nil {
				return xerrors.Errorf("put error: %w", err)
			}
		}
	}

	// All advisories with codename and fixed version are inserted into DB here.
	for bkt, advisory := range vs.bktAdvisories {
		if err := vs.put(tx, bkt, advisory); err != nil {
			return xerrors.Errorf("put error: %w", err)
		}
	}
	return nil
}

func (vs VulnSrc) put(tx *bolt.Tx, bkt bucket, advisory types.Advisory) error {
	// Convert codename to major version
	// e.g. "buster" => "10"
	majorVersion, ok := vs.distributions[bkt.codeName]
	if !ok {
		// Stale codename such as squeeze and sarge
		return nil
	}

	var platform string
	if advisory.FixedVersion == "" {
		// Convert major version to bucket name for unfixed vulnerabilities
		// e.g. "10" => "debian 10"
		platform = fmt.Sprintf(platformFormat, majorVersion)

	} else {
		// Convert major version to bucket name for fixed vulnerabilities
		// e.g. "10" => "debian oval 10"
		platform = fmt.Sprintf(ovalPlatformFormat, majorVersion)
	}

	if err := vs.dbc.PutAdvisoryDetail(tx, bkt.vulnID, platform, bkt.pkgName, advisory); err != nil {
		return xerrors.Errorf("failed to save Debian advisory: %w", err)
	}

	// for light DB
	if err := vs.dbc.PutSeverity(tx, bkt.vulnID, types.SeverityUnknown); err != nil {
		return xerrors.Errorf("failed to save Debian vulnerability severity: %w", err)
	}

	return nil
}

func (vs VulnSrc) Get(release string, pkgName string) ([]types.Advisory, error) {
	// For unfixed vulnerabilities
	bkt := fmt.Sprintf(platformFormat, release)
	unfixedAdvs, err := vs.dbc.GetAdvisories(bkt, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get Debian advisories: %w", err)
	}

	// For fixed vulnerabilities
	ovalBkt := fmt.Sprintf(ovalPlatformFormat, release)
	fixedAdvs, err := vs.dbc.GetAdvisories(ovalBkt, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get Debian OVAL advisories: %w", err)
	}
	return append(fixedAdvs, unfixedAdvs...), nil
}

func severityFromUrgency(urgency string) types.Severity {
	switch urgency {
	case "not yet assigned", "end-of-life":
		return types.SeverityUnknown

	case "unimportant", "low", "low*", "low**":
		return types.SeverityLow

	case "medium", "medium*", "medium**":
		return types.SeverityMedium

	case "high", "high*", "high**":
		return types.SeverityHigh
	default:
		return types.SeverityUnknown
	}
}

func (vs VulnSrc) parseDistributions(rootDir string) error {
	log.Println("  Parsing distributions...")
	f, err := os.Open(filepath.Join(rootDir, distributionsFile))
	if err != nil {
		return xerrors.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	// To parse distributions.json
	var parsed map[string]struct {
		MajorVersion string `json:"major-version"`
	}
	if err = json.NewDecoder(f).Decode(&parsed); err != nil {
		return xerrors.Errorf("failed to decode Debian distribution JSON: %w", err)
	}
	for dist, val := range parsed {
		if val.MajorVersion == "" {
			// Empty code refers to sid(development) codeName
			//vs.distributions[dist] = defaultCode
			continue
		}
		vs.distributions[dist] = val.MajorVersion
	}
	return nil
}

func (vs VulnSrc) parseSources(dir string) error {
	for code := range vs.distributions {
		codePath := filepath.Join(dir, code)
		if ok, _ := utils.Exists(codePath); !ok {
			continue
		}

		log.Printf("  Parsing %s sources...", code)
		err := utils.FileWalk(codePath, func(r io.Reader, path string) error {
			// To parse Sources.json
			var pkgs []struct {
				Package []string
				Version []string
			}
			if err := json.NewDecoder(r).Decode(&pkgs); err != nil {
				return xerrors.Errorf("failed to decode %s: %w", path, err)
			}

			for _, pkg := range pkgs {
				if len(pkg.Package) == 0 || len(pkg.Version) == 0 {
					continue
				}

				bkt := bucket{
					codeName: code,
					pkgName:  pkg.Package[0],
				}

				version := pkg.Version[0]

				// Skip the update when the stored version is greater than the processing version.
				if v, ok := vs.pkgVersions[bkt]; ok {
					res, err := compareVersions(v, version)
					if err != nil {
						return xerrors.Errorf("version comparison error: %w", err)
					}

					if res >= 0 {
						continue
					}
				}

				// Store package name and version per codename
				vs.pkgVersions[bkt] = version
			}

			return nil
		})
		if err != nil {
			return xerrors.Errorf("filepath walk error: %w", err)
		}
	}

	return nil
}

// There are 3 cases when the fixed version of each release is not stated in list files.
//
// Case 1
//   When the latest version in the release is greater than the fixed version in sid,
//   we can assume that the vulnerability was already fixed at the fixed version.
//   e.g.
//	   latest version (buster) : "5.0-4"
//     fixed version (sid)     : "5.0-2"
//      => the vulnerability was fixed at "5.0-2".
//
// Case 2
//   When the latest version in the release less than the fixed version in sid,
//   it means the vulnerability has not been fixed yet.
//   e.g.
//	   latest version (buster) : "5.0-4"
//     fixed version (sid)     : "5.0-5"
//      => the vulnerability hasn't been fixed yet.
//
// Case 3
//   When the fixed version in sid is empty,
//   it means the vulnerability has not been fixed yet.
//   e.g.
//	   latest version (buster) : "5.0-4"
//     fixed version (sid)     : ""
//      => the vulnerability hasn't been fixed yet.
func hasFixedVersion(sidVer, codeVer string) (bool, error) {
	// No fixed version even in sid
	if sidVer == "" {
		return false, nil
	}

	res, err := compareVersions(codeVer, sidVer)
	if err != nil {
		return false, xerrors.Errorf("version comparison error")
	}

	// Greater than or equal
	return res >= 0, nil
}

func compareVersions(v1, v2 string) (int, error) {
	// v1 or v2 might be empty.
	switch {
	case v1 == "" && v2 == "":
		return 0, nil
	case v1 == "":
		return -1, nil
	case v2 == "":
		return 1, nil
	}

	ver1, err := version.NewVersion(v1)
	if err != nil {
		return 0, xerrors.Errorf("version error: %w", err)
	}

	ver2, err := version.NewVersion(v2)
	if err != nil {
		return 0, xerrors.Errorf("version error: %w", err)
	}

	return ver1.Compare(ver2), nil
}
