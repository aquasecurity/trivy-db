package debian

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	version "github.com/knqyf263/go-deb-version"
	"github.com/knqyf263/nested"
	"golang.org/x/xerrors"
)

const (
	debianDir         = "debian"
	distributionsFile = "distributions.json"
	packageType       = "package"
	xrefType          = "xref"
	packageDir        = "Packages"
	packageFile       = "Packages.json"
)

var (
	// e.g. debian 8
	platformFormat      = "debian %s"
	defaultCode         = "unstable"
	internalPackageDirs = []string{
		"contrib", "main",
	}
	// debianReleasesMapping = map[string]string{
	// 	// Code names
	// 	"squeeze": "6",
	// 	"wheezy":  "7",
	// 	"jessie":  "8",
	// 	"stretch": "9",
	// 	"buster":  "10",
	// 	"sid":     "unstable",
	// }
	vulnDirs = []string{
		"CVE",
		"DLA",
		"DSA",
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

func (vs VulnSrc) parseDebianFiles(dir string) (nested.Nested, error) {
	buckets := nested.Nested{}
	rootDir := filepath.Join(dir, "vuln-list", debianDir)
	debianReleasesMapping, err := getDistributions(rootDir)
	if err != nil {
		return buckets, xerrors.Errorf("error in debain distributions walking: %w", err)
	}

	allPackages, err := getAllPackages(rootDir, debianReleasesMapping)
	if err != nil {
		return buckets, xerrors.Errorf("error in debain packages walking: %w", err)
	}

	for _, vulnDir := range vulnDirs {
		joindDir := filepath.Join(rootDir, vulnDir)
		err = utils.FileWalk(joindDir, func(r io.Reader, path string) error {
			var srcJson DebianSrcCVE
			if err := json.NewDecoder(r).Decode(&srcJson); err != nil {
				return nil
			}

			vulnId := srcJson.Header.VulnerabilityID
			releases := []string{}
			toSearchPkgs := map[string]VulnDetail{}
			linkedCVEs := []string{}

			for _, annotation := range srcJson.Annotations {
				if annotation.Type == xrefType {
					// Will be first object of list or absent
					linkedCVEs = annotation.Bugs
					continue
				}
				if annotation.Type != packageType || annotation.State == "not-affected" {
					continue
				}

				if annotation.Release != "" {
					releases = append(releases, annotation.Release)
				}

				bucketName := getBucketName(annotation.Release, debianReleasesMapping)
				if bucketName == "" {
					// Considering release as outdated
					continue
				}
				packageName := annotation.Package

				description := annotation.Description
				if description == "" {
					description = srcJson.Header.Description
				}

				vulnDetail := VulnDetail{
					FixedVersion: annotation.Version,
					State:        annotation.State,
					Description:  description,
					Severity:     severityFromUrgency(annotation.Severity),
				}
				if vulnDir != "CVE" {
					// Update the vendor IDs
					// While parsing DSA and DLA vulnerabilities check if
					// connected CVE wih same release, package and fixed Version
					// is present
					// if yes, append the vendor ID
					// if no, add vendor
					for _, cve := range linkedCVEs {
						detail, err := buckets.Get([]string{
							bucketName,
							packageName,
							cve,
						})
						var cveDetail VulnDetail
						if err == nil {
							if detail.(VulnDetail).FixedVersion != vulnDetail.FixedVersion {
								continue
							}
							cveDetail = detail.(VulnDetail)
							cveDetail.VendorIds = append(cveDetail.VendorIds, vulnId)
						} else if err == nested.ErrNoSuchKey {
							cveDetail = VulnDetail{
								FixedVersion: vulnDetail.FixedVersion,
								State:        vulnDetail.State,
								Description:  vulnDetail.Description,
								Severity:     severityFromUrgency(annotation.Severity),
								VendorIds:    []string{vulnId},
							}
						} else {
							return xerrors.Errorf("Failed adding vendor %s, to cve %s: %w", vulnId, cve, err)
						}

						buckets.Set([]string{
							bucketName,
							packageName,
							cve,
						}, cveDetail)
					}
				}

				if annotation.Version != "" && annotation.Release == "" {
					// Fixed version found but release is sid
					toSearchPkgs[packageName] = vulnDetail
				}

				buckets.Set([]string{
					bucketName,
					packageName,
					vulnId,
				}, vulnDetail)
			}

			for pack, detail := range toSearchPkgs {
				for release := range allPackages {
					if utils.StringInSlice(release, releases) {
						// do not parse pacakages for known release
						continue
					}
					maxVersion, _ := allPackages.Get([]string{release, pack})
					if maxVersion == nil || maxVersion == "" {
						continue
					}
					if val, _ := debianVersionCompare(maxVersion.(string), detail.FixedVersion); val >= 0 {
						bucketName := getBucketName(release, debianReleasesMapping)
						if bucketName == "" {
							continue
						}
						buckets.Set([]string{
							bucketName,
							pack,
							vulnId,
						}, detail)
					}
				}
			}

			return nil
		})
		if err != nil {
			return buckets, err
		}
	}
	return buckets, nil
}

func (vs VulnSrc) Update(dir string) error {

	buckets, err := vs.parseDebianFiles(dir)
	if err != nil {
		return xerrors.Errorf("error in Debian parse: %w", err)
	}
	if err = vs.Save(buckets); err != nil {
		return xerrors.Errorf("error in Debian save: %w", err)
	}

	return nil
}

func (vs VulnSrc) Save(buckets nested.Nested) error {
	log.Println("Saving Debian DB")
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, buckets)
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}
	log.Println("Saved Debian DB")
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, buckets nested.Nested) error {

	for platform, val1 := range buckets {
		packages := val1.(map[string]interface{})
		for packageName, val2 := range packages {
			vulns := val2.(map[string]interface{})
			for vulnId, advisory := range vulns {
				if err := vs.dbc.PutAdvisoryDetail(tx, vulnId, platform, packageName, advisory); err != nil {
					return xerrors.Errorf("failed to save Debian advisory: %w", err)
				}
				vuln := types.VulnerabilityDetail{
					Severity:    advisory.(VulnDetail).Severity,
					Description: advisory.(VulnDetail).Description,
				}
				if err := vs.dbc.PutVulnerabilityDetail(tx, vulnId, vulnerability.Debian, vuln); err != nil {
					return xerrors.Errorf("failed to save Debian vulnerability: %w", err)
				}
				// for light DB
				if err := vs.dbc.PutSeverity(tx, vulnId, types.SeverityUnknown); err != nil {
					return xerrors.Errorf("failed to save Debian vulnerability severity: %w", err)
				}

			}
		}
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

func getDistributions(rootDir string) (map[string]string, error) {
	dists := map[string]string{}
	f, err := os.Open(filepath.Join(rootDir, distributionsFile))
	if err != nil {
		return dists, xerrors.Errorf("failed to open file: %w", err)
	}
	defer f.Close()
	var tmp map[string]struct {
		Version string `json:"major-version"`
	}
	if err := json.NewDecoder(f).Decode(&tmp); err != nil {
		return dists, xerrors.Errorf("failed to decode Debian distribution JSON: %w", err)
	}
	for dist, val := range tmp {
		if val.Version == "" {
			// Empty code refers to sid(development) release
			dists[dist] = defaultCode
			continue
		}
		dists[dist] = val.Version
	}
	return dists, nil
}

func getBucketName(release string, debianReleasesMapping map[string]string) (bucketName string) {

	if code, ok := debianReleasesMapping[release]; ok {
		return fmt.Sprintf(platformFormat, code)
	} else if release == "" {
		// sid release
		return fmt.Sprintf(platformFormat, defaultCode)
	} else {
		// Outdated releases
		return ""
	}
}

func getAllPackages(rootDir string, debianReleasesMapping map[string]string) (nested.Nested, error) {
	packages := nested.Nested{}
	for code := range debianReleasesMapping {
		codePath := filepath.Join(rootDir, packageDir, code)
		if ok, _ := utils.Exists(codePath); !ok {
			continue
		}
		for _, internalDir := range internalPackageDirs {
			f, err := os.Open(filepath.Join(codePath, internalDir, packageFile))
			if err != nil && !os.IsNotExist(err) {
				return nil, xerrors.Errorf("failed to open file: %w", err)
			}
			defer f.Close()
			tmp := []struct {
				Package []string `json:"Package"`
				Version []string `json:"Version"`
			}{}
			if err := json.NewDecoder(f).Decode(&tmp); err != nil {
				return nil, xerrors.Errorf("failed to decode Debian distribution JSON: %w", err)
			}

			for _, val := range tmp {
				if len(val.Package) < 1 || len(val.Version) < 1 {
					continue
				}
				packages.Set([]string{code, val.Package[0]}, val.Version[0])
			}
		}
	}
	return packages, nil
}

func debianVersionCompare(a string, b string) (int, error) {
	v1, err := version.NewVersion(a)
	if err != nil {
		return 0, err
	}
	v2, err := version.NewVersion(b)
	if err != nil {
		return 0, err
	}
	return v1.Compare(v2), nil
}
