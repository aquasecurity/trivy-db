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
)

const (
	debianDir = "debian"

	// Type
	packageType = "package"
	xrefType    = "xref"

	// File or directory to parse
	distributionsFile = "parseDistributions.json"
	packageDir        = "Packages"
	cveDir            = "CVE"
	dlaDir            = "DLA"
	dsaDir            = "DSA"

	// e.g. debian 8
	platformFormat = "debian %s"
)

var (
	skipStatuses = []string{"not-affected", "removed", "undetermined"}
)

type VulnSrc struct {
	dbc db.Operation

	// Hold a map of codenames and major versions
	// e.g. "buster" => "10"
	distributions map[string]string

	// Hold the latest versions of each codename
	// e.g. {"buster", "bash"} => "5.0-4"
	pkgVersions map[bucket]string

	// Hold the fixed versions of vulnerabilities in sid
	// e.g. {"putty", "CVE-2021-36367"} => "0.75-3" // fixed vulnerability
	//      {"ndpi",  "CVE-2021-36082"} => ""       // unfixed vulnerability
	sidFixedVersions map[bucket]string

	// Hold debian advisories
	// e.g. {"buster", "connman", "CVE-2021-33833"} => {"FixedVersion": 1.36-2.1~deb10u2, ...}
	bktAdvisories map[bucket]types.Advisory
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc:              db.Config{},
		distributions:    map[string]string{},
		pkgVersions:      map[bucket]string{},
		sidFixedVersions: map[bucket]string{},
		bktAdvisories:    map[bucket]types.Advisory{},
	}
}

func (vs VulnSrc) Name() string {
	return vulnerability.Debian
}

func (vs VulnSrc) Update(dir string) error {
	if err := vs.parse(dir); err != nil {
		return xerrors.Errorf("error in Debian parse: %w", err)
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

	// Parse Packages/**.json
	if err := vs.parsePackages(rootDir); err != nil {
		return xerrors.Errorf("packages walking: %w", err)
	}

	// Parse CVE/*.json
	if err := vs.parseCVE(dir); err != nil {
		return xerrors.Errorf("CVE error: %w", err)
	}

	// Parse DLA/*.json
	if err := vs.parseDLA(dir); err != nil {
		return xerrors.Errorf("DLA error: %w", err)
	}

	// Parse DSA/*.json
	if err := vs.parseDSA(dir); err != nil {
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
	err := vs.parseBug(filepath.Join(dir, cveDir), func(bug Bug) error {
		cveID := bug.Header.ID
		for _, ann := range bug.Annotations {
			if ann.Type != packageType {
				continue
			} else if utils.StringInSlice(ann.Kind, skipStatuses) {
				continue
			}

			// For sid
			if ann.Release == "" {
				vs.sidFixedVersions[bucket{
					pkgName: ann.Package,
					cveID:   cveID,
				}] = ann.Version // it will be empty for unfixed vulnerabilities
			} else if ann.Release != "" {
				advisory := types.Advisory{
					FixedVersion: ann.Version, // this is supposed to be empty
				}
				vs.bktAdvisories[bucket{
					codeName: ann.Release,
					pkgName:  ann.Package,
					cveID:    cveID,
				}] = advisory
			}
		}

		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (vs VulnSrc) parseDLA(dir string) error {
	if err := vs.parseAdvisory(filepath.Join(dir, dlaDir)); err != nil {
		return xerrors.Errorf("DLA parse error: %w", err)
	}
	return nil
}

func (vs VulnSrc) parseDSA(dir string) error {
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
			} else if utils.StringInSlice(ann.Kind, skipStatuses) {
				continue
			}

			for _, cveID := range cveIDs {
				bkt := bucket{
					codeName: ann.Release,
					pkgName:  ann.Package,
					cveID:    cveID,
				}

				adv, ok := vs.bktAdvisories[bkt]
				if ok {
					res, err := compareVersions(ann.Version, adv.FixedVersion)
					if err != nil {
						return xerrors.Errorf("version error: %w", err)
					}
					// TODO: fix
					if res != 0 {
						log.Println(advisoryID)
						adv.FixedVersion = ann.Version
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
		return xerrors.Errorf("error in batch update: %w", err)
	}
	log.Println("Saved Debian DB")
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx) error {
	// Iterate all pairs of package name and CVE-ID in sid
	for sidBkt, sidVer := range vs.sidFixedVersions {
		pkgName := sidBkt.pkgName
		cveID := sidBkt.cveID

		// Iterate all codenames, e.g. buster
		for code := range vs.distributions {
			bkt := bucket{
				codeName: code,
				pkgName:  pkgName,
				cveID:    cveID,
			}

			// Check if the advisory already exists for the codename
			// If yes, it will be inserted into DB
			if adv, ok := vs.bktAdvisories[bkt]; ok {
				if err := vs.put(tx, bkt, adv); err != nil {
					return xerrors.Errorf("put error: %w", err)
				}
				continue
			}

			// If no, the fixed version needs to be determined by comparing with the fixed version in sid.
			bkt = bucket{
				codeName: code,
				pkgName:  pkgName,
			}

			// Get the latest version in the release
			// e.g. {"buster", "bash"} => "5.0-4"
			codeVer, ok := vs.pkgVersions[bkt]
			if !ok {
				continue
			}

			// Check if the release has the fixed version
			fixed, err := hasFixedVersion(sidVer, codeVer)
			if err != nil {
				return err
			}

			adv := types.Advisory{}
			if fixed {
				adv.FixedVersion = sidVer
			}

			bkt.cveID = cveID
			if err = vs.put(tx, bkt, adv); err != nil {
				return xerrors.Errorf("put error: %w", err)
			}
		}
	}

	return nil
}

func (vs VulnSrc) put(tx *bolt.Tx, bkt bucket, advisory types.Advisory) error {
	// Convert codename to major version
	// e.g. "buster" => "10"
	majorVersion, ok := vs.distributions[bkt.codeName]
	if !ok {
		return xerrors.Errorf("unknown codename: %s", bkt.codeName)
	}

	// Convert major version to bucket name
	// e.g. "10" => "debian 10"
	platform := fmt.Sprintf(platformFormat, majorVersion)

	if err := vs.dbc.PutAdvisoryDetail(tx, bkt.cveID, platform, bkt.pkgName, advisory); err != nil {
		return xerrors.Errorf("failed to save Debian advisory: %w", err)
	}

	// for light DB
	if err := vs.dbc.PutSeverity(tx, bkt.cveID, types.SeverityUnknown); err != nil {
		return xerrors.Errorf("failed to save Debian vulnerability severity: %w", err)
	}

	return nil
}

func (vs VulnSrc) Get(release string, pkgName string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, release)
	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get Debian advisories: %w", err)
	}
	return advisories, nil
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

func (vs VulnSrc) parsePackages(rootDir string) error {
	for code := range vs.distributions {
		codePath := filepath.Join(rootDir, packageDir, code)
		err := utils.FileWalk(codePath, func(r io.Reader, path string) error {
			// To parse Packages.json
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

				// Store package name and version per codename
				vs.pkgVersions[bucket{
					codeName: code,
					pkgName:  pkg.Package[0],
				}] = pkg.Version[0]
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
		return false, err
	}

	// Greater than or equal
	return res >= 0, nil
}

func compareVersions(v1, v2 string) (int, error) {
	ver1, err := version.NewVersion(v1)
	if err != nil {
		return 0, err
	}

	ver2, err := version.NewVersion(v2)
	if err != nil {
		return 0, err
	}

	return ver1.Compare(ver2), nil
}
