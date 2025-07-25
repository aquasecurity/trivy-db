package debian

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	debver "github.com/knqyf263/go-deb-version"
	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	debianDir = "vuln-list-debian"

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

	// e.g. debian 8
	platformFormat = "debian %s"
)

var (
	// NOTE: "removed" should not be marked as "not-affected".
	// ref. https://security-team.debian.org/security_tracker.html#removed-packages
	skipStatuses = []string{
		"not-affected",
		"undetermined",
	}

	source = types.DataSource{
		ID:   vulnerability.Debian,
		Name: "Debian Security Tracker",
		URL:  "https://salsa.debian.org/security-tracker-team/security-tracker",
	}
)

type Option func(src *VulnSrc)

func WithCustomPut(put db.CustomPut) Option {
	return func(src *VulnSrc) {
		src.put = put
	}
}

type VulnSrc struct {
	put    db.CustomPut
	dbc    db.Operation
	logger *log.Logger

	// Hold a map of codenames and major versions from distributions.json
	// e.g. "buster" => "10"
	distributions map[string]string

	// Hold vulnerability details per vulnerability id
	// e.g. {"CVE-2021-33560": "Libgcrypt before 1.8.8 and 1.9.x before 1.9.3 mishandles ElGamal encry ..."}
	details map[string]VulnerabilityDetail

	// Hold the latest versions of each codename in Sources.json
	// e.g. {"buster", "bash"} => "5.0-4"
	pkgVersions map[bucket]string

	// Hold the fixed versions of vulnerabilities in sid
	// e.g. {"putty", "CVE-2021-36367"} => "0.75-3" // fixed vulnerability
	//      {"ndpi",  "CVE-2021-36082"} => ""       // unfixed vulnerability
	sidFixedVersions map[bucket]string

	// Hold debian advisories
	// e.g. {"buster", "connman", "CVE-2021-33833"} => {"FixedVersion": 1.36-2.1~deb10u2, ...}
	bktAdvisories map[bucket]Advisory

	// Hold not-affected versions
	// e.g. {"buster", "linux", "CVE-2021-3739"} => {}
	notAffected map[bucket]struct{}
}

func NewVulnSrc(opts ...Option) VulnSrc {
	src := VulnSrc{
		put:              defaultPut,
		dbc:              db.Config{},
		logger:           log.WithPrefix("debian"),
		distributions:    map[string]string{},
		details:          map[string]VulnerabilityDetail{},
		pkgVersions:      map[bucket]string{},
		sidFixedVersions: map[bucket]string{},
		bktAdvisories:    map[bucket]Advisory{},
		notAffected:      map[bucket]struct{}{},
	}

	for _, opt := range opts {
		opt(&src)
	}

	return src
}

func (vs VulnSrc) Name() types.SourceID {
	return source.ID
}

func (vs VulnSrc) Update(dir string) error {
	eb := oops.In("debian")
	if err := vs.parse(dir); err != nil {
		return eb.Wrapf(err, "parse error")
	}

	if err := vs.save(); err != nil {
		return eb.Wrapf(err, "save error")
	}

	return nil
}

func (vs VulnSrc) parse(dir string) error {
	rootDir := filepath.Join(dir, debianDir, "tracker")
	eb := oops.With("root_dir", rootDir)

	// Parse distributions.json
	if err := vs.parseDistributions(rootDir); err != nil {
		return eb.Wrapf(err, "distributions error")
	}

	// Parse source/**.json
	if err := vs.parseSources(filepath.Join(rootDir, sourcesDir)); err != nil {
		return eb.Wrapf(err, "source parse error")
	}

	// Parse updates-source/**.json
	if err := vs.parseSources(filepath.Join(rootDir, updateSourcesDir)); err != nil {
		return eb.Wrapf(err, "updates-source parse error")
	}

	// Parse CVE/*.json
	if err := vs.parseCVE(rootDir); err != nil {
		return eb.Wrapf(err, "CVE error")
	}

	// Parse DLA/*.json
	if err := vs.parseDLA(rootDir); err != nil {
		return eb.Wrapf(err, "DLA error")
	}

	// Parse DSA/*.json
	if err := vs.parseDSA(rootDir); err != nil {
		return eb.Wrapf(err, "DSA error")
	}

	return nil
}

func (vs VulnSrc) parseBug(dir string, fn func(bug) error) error {
	eb := oops.With("dir", dir)
	err := utils.FileWalk(dir, func(r io.Reader, path string) error {
		eb := eb.With("file_path", path)
		var bg bug
		if err := json.NewDecoder(r).Decode(&bg); err != nil {
			return eb.Wrapf(err, "json decode error")
		}

		if err := fn(bg); err != nil {
			return eb.Wrapf(err, "parse debian bug error")
		}
		return nil
	})

	if err != nil {
		return eb.Wrapf(err, "walk error")
	}
	return nil
}

func (vs VulnSrc) parseCVE(dir string) error {
	vs.logger.Info("Parsing CVE JSON files...")
	err := vs.parseBug(filepath.Join(dir, cveDir), func(bug bug) error {
		// Hold severities per the packages
		severities := map[string]string{}
		cveID := bug.Header.ID
		vs.details[cveID] = VulnerabilityDetail{
			Description: strings.Trim(bug.Header.Description, "()"),
		}

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
			if slices.Contains(skipStatuses, ann.Kind) {
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
					severities[ann.Package] = ann.Severity
					sidBkt.severity = ann.Severity
				}

				vs.sidFixedVersions[sidBkt] = ann.Version // it may be empty for unfixed vulnerabilities

				continue
			}

			fixedVersion := ann.Version
			kind := ann.Kind
			if latestVersion, ok := vs.pkgVersions[bucket{codeName: ann.Release, pkgName: ann.Package}]; ok {
				// If the fixed version has not yet been released, then set the state to "unfixed".
				if comp, err := compareVersions(latestVersion, fixedVersion); err == nil && comp < 0 {
					fixedVersion = ""
					if kind == "fixed" {
						kind = "unfixed"
					}
				}
			}

			advisory := Advisory{
				FixedVersion: fixedVersion, // It might be empty because of no-dsa.
				Severity:     severities[ann.Package],
			}

			if fixedVersion == "" {
				// Populate State only when FixedVersion is empty.
				// e.g. no-dsa
				advisory.State = kind
			}

			// This advisory might be overwritten by DLA/DSA.
			vs.bktAdvisories[bkt] = advisory
		}

		return nil
	})
	if err != nil {
		return oops.Wrapf(err, "CVE parse error")
	}
	return nil
}

func (vs VulnSrc) parseDLA(dir string) error {
	vs.logger.Info("Parsing DLA JSON files...")
	if err := vs.parseAdvisory(filepath.Join(dir, dlaDir)); err != nil {
		return oops.Wrapf(err, "DLA parse error")
	}
	return nil
}

func (vs VulnSrc) parseDSA(dir string) error {
	vs.logger.Info("Parsing DSA JSON files...")
	if err := vs.parseAdvisory(filepath.Join(dir, dsaDir)); err != nil {
		return oops.Wrapf(err, "DSA parse error")
	}
	return nil
}

func (vs VulnSrc) parseAdvisory(dir string) error {
	return vs.parseBug(dir, func(bug bug) error {
		var cveIDs []string
		advisoryID := bug.Header.ID
		vs.details[advisoryID] = VulnerabilityDetail{
			Description: strings.Trim(bug.Header.Description, "()"),
		}

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
				eb := oops.With("vuln_id", vulnID).With("package_name", ann.Package).With("code_name", ann.Release)

				// Skip not-affected, removed or undetermined advisories
				if slices.Contains(skipStatuses, ann.Kind) {
					vs.notAffected[bkt] = struct{}{}
					continue
				}

				adv, ok := vs.bktAdvisories[bkt]
				if ok {
					// If some advisories fix the same CVE-ID, the latest version will be taken.
					// We assume that the first fix was insufficient and the next advisory fixed it correctly.
					res, err := compareVersions(ann.Version, adv.FixedVersion)
					if err != nil {
						return eb.Wrapf(err, "version error")
					}

					// Replace the fixed version with the newer version.
					if res > 0 {
						adv.FixedVersion = ann.Version
						adv.State = "" // State should be empty because this advisory has fixed version, actually.
					}
					adv.VendorIDs = append(adv.VendorIDs, advisoryID)
				} else {
					adv = Advisory{
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
	vs.logger.Info("Saving DB")
	err := vs.dbc.BatchUpdate(vs.commit)
	if err != nil {
		return oops.Wrapf(err, "batch update error")
	}
	vs.logger.Info("Saved DB")
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx) error {
	// Iterate all pairs of package name and CVE-ID in sid
	for sidBkt, sidVer := range vs.sidFixedVersions {
		pkgName := sidBkt.pkgName
		cveID := sidBkt.vulnID

		// Skip if the advisory is stated as "not-affected" for all distributions.
		if _, ok := vs.notAffected[bucket{
			pkgName: pkgName,
			vulnID:  cveID,
		}]; ok {
			continue
		}

		// Iterate all codenames, e.g. buster
		for code := range vs.distributions {
			bkt := bucket{
				codeName: code,
				pkgName:  pkgName,
				vulnID:   cveID,
			}
			eb := oops.With("sid", sidVer).With("package_name", pkgName).With("vuln_id", cveID).With("code_name", code)

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
				return eb.Wrapf(err, "version error")
			}

			if fixed {
				adv.FixedVersion = sidVer
				adv.State = "" // Overwrite state such as "no-dsa" and "postponed" because it is wrong.
				delete(vs.bktAdvisories, bkt)
			}

			// Add severity
			adv.Severity = sidBkt.severity

			bkt.vulnID = cveID
			if err = vs.putAdvisory(tx, bkt, adv); err != nil {
				return eb.Wrapf(err, "put advisory error")
			}
		}
	}

	// All advisories with codename and fixed version are inserted into DB here.
	for bkt, advisory := range vs.bktAdvisories {
		if err := vs.putAdvisory(tx, bkt, advisory); err != nil {
			return oops.Wrapf(err, "put advisory error")
		}
	}
	return nil
}

func (vs VulnSrc) putAdvisory(tx *bolt.Tx, bkt bucket, advisory Advisory) error {
	// Convert codename to major version
	// e.g. "buster" => "10"
	majorVersion, ok := vs.distributions[bkt.codeName]
	if !ok {
		// Stale codename such as squeeze and sarge
		return nil
	}

	// Fill information for the buckets.
	advisory.VulnerabilityID = bkt.vulnID
	advisory.PkgName = bkt.pkgName
	advisory.Platform = fmt.Sprintf(platformFormat, majorVersion)
	advisory.Title = vs.details[bkt.vulnID].Description // The Debian description is short, so we'll use it as a title.

	eb := oops.With("vuln_id", advisory.VulnerabilityID).With("package_name", advisory.PkgName).With("platform", advisory.Platform)
	if err := vs.put(vs.dbc, tx, advisory); err != nil {
		return eb.Wrapf(err, "put error")
	}

	return nil
}

// defaultPut puts the advisory into Trivy DB, but it can be overwritten.
func defaultPut(dbc db.Operation, tx *bolt.Tx, advisory any) error {
	adv, ok := advisory.(Advisory)
	if !ok {
		return oops.Errorf("unknown type")
	}

	detail := types.Advisory{
		VendorIDs:    adv.VendorIDs,
		Status:       newStatus(adv.State),
		Severity:     severityFromUrgency(adv.Severity),
		FixedVersion: adv.FixedVersion,
	}

	if err := dbc.PutAdvisoryDetail(tx, adv.VulnerabilityID, adv.PkgName, []string{adv.Platform}, &detail); err != nil {
		return oops.Wrapf(err, "failed to save advisory")
	}

	vuln := types.VulnerabilityDetail{
		Title: adv.Title,
	}
	if err := dbc.PutVulnerabilityDetail(tx, adv.VulnerabilityID, source.ID, vuln); err != nil {
		return oops.Wrapf(err, "failed to save vulnerability detail")
	}

	// for optimization
	if err := dbc.PutVulnerabilityID(tx, adv.VulnerabilityID); err != nil {
		return oops.Wrapf(err, "failed to save vulnerability ID")
	}

	if err := dbc.PutDataSource(tx, adv.Platform, source); err != nil {
		return oops.Wrapf(err, "failed to put data source")
	}

	return nil
}

func (vs VulnSrc) Get(params db.GetParams) ([]types.Advisory, error) {
	eb := oops.In("debian").With("release", params.Release).With("package_name", params.PkgName)
	bkt := fmt.Sprintf(platformFormat, params.Release)
	advisories, err := vs.dbc.GetAdvisories(bkt, params.PkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get advisories")
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
	vs.logger.Info("Parsing distributions...")
	filePath := filepath.Join(rootDir, distributionsFile)
	eb := oops.With("root_dir", rootDir).With("file_path", filePath)

	f, err := os.Open(filePath)
	if err != nil {
		return eb.Wrapf(err, "failed to open file")
	}
	defer f.Close()

	// To parse distributions.json
	var parsed map[string]struct {
		MajorVersion string `json:"major-version"`
	}
	if err = json.NewDecoder(f).Decode(&parsed); err != nil {
		return eb.Wrapf(err, "json decode error")
	}
	for dist, val := range parsed {
		if val.MajorVersion == "" {
			// Empty code refers to sid(development) codeName
			// vs.distributions[dist] = defaultCode
			continue
		}
		vs.distributions[dist] = val.MajorVersion
	}
	return nil
}

func (vs VulnSrc) parseSources(dir string) error {
	eb := oops.With("dir", dir)
	for code := range vs.distributions {
		codePath := filepath.Join(dir, code)
		if ok, _ := utils.Exists(codePath); !ok {
			continue
		}
		eb = eb.With("code_name", code)

		vs.logger.Info("Parsing sources...", log.String("code", code))
		err := utils.FileWalk(codePath, func(r io.Reader, path string) error {
			eb := eb.With("file_path", path)

			// To parse Sources.json
			var pkg struct {
				Package []string
				Version []string
			}
			if err := json.NewDecoder(r).Decode(&pkg); err != nil {
				return eb.Wrapf(err, "json decode error")
			}

			if len(pkg.Package) == 0 || len(pkg.Version) == 0 {
				return nil
			}

			bkt := bucket{
				codeName: code,
				pkgName:  pkg.Package[0],
			}

			version := pkg.Version[0]
			eb = eb.With("pkg_name", bkt.pkgName).With("version", version)

			// Skip the update when the stored version is greater than the processing version.
			if v, ok := vs.pkgVersions[bkt]; ok {
				res, err := compareVersions(v, version)
				if err != nil {
					return eb.Wrapf(err, "version comparison error")
				}

				if res >= 0 {
					return nil
				}
			}

			// Store package name and version per codename
			vs.pkgVersions[bkt] = version

			return nil
		})
		if err != nil {
			return eb.Wrapf(err, "walk error")
		}
	}

	return nil
}

// There are 3 cases when the fixed version of each release is not stated in list files.
//
// Case 1
//
//	  When the latest version in the release is greater than the fixed version in sid,
//	  we can assume that the vulnerability was already fixed at the fixed version.
//	  e.g.
//		latest version (buster) : "5.0-4"
//	    fixed version (sid)     : "5.0-2"
//	    => the vulnerability was fixed at "5.0-2".
//
// Case 2
//
//	  When the latest version in the release less than the fixed version in sid,
//	  it means the vulnerability has not been fixed yet.
//	  e.g.
//		latest version (buster) : "5.0-4"
//	    fixed version (sid)     : "5.0-5"
//	     => the vulnerability hasn't been fixed yet.
//
// Case 3
//
//	  When the fixed version in sid is empty,
//	  it means the vulnerability has not been fixed yet.
//	  e.g.
//		   latest version (buster) : "5.0-4"
//	    fixed version (sid)     : ""
//	     => the vulnerability hasn't been fixed yet.
func hasFixedVersion(sidVer, codeVer string) (bool, error) {
	// No fixed version even in sid
	if sidVer == "" {
		return false, nil
	}

	eb := oops.With("sid_ver", sidVer).With("code_ver", codeVer)

	res, err := compareVersions(codeVer, sidVer)
	if err != nil {
		return false, eb.Wrapf(err, "version comparison error")
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

	ver1, err := debver.NewVersion(v1)
	if err != nil {
		return 0, oops.Wrapf(err, "version error")
	}

	ver2, err := debver.NewVersion(v2)
	if err != nil {
		return 0, oops.Wrapf(err, "version error")
	}

	return ver1.Compare(ver2), nil
}

func newStatus(s string) types.Status {
	switch strings.ToLower(s) {
	// "end-of-life" is considered as vulnerable
	// e.g. https://security-tracker.debian.org/tracker/CVE-2022-1488
	case "no-dsa", "unfixed":
		return types.StatusAffected
	case "ignored":
		return types.StatusWillNotFix
	case "postponed":
		return types.StatusFixDeferred
	case "end-of-life":
		return types.StatusEndOfLife
	}
	return types.StatusUnknown
}
