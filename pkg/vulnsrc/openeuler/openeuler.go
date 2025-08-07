package openeuler

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/samber/lo"
	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const openEulerFormat = "openEuler-%s"

var (
	eulerDir = "openeuler"

	source = types.DataSource{
		ID:   vulnerability.OpenEuler,
		Name: "openEuler CVRF",
		URL:  "https://repo.openeuler.org/security/data/cvrf",
	}
)

type PutInput struct {
	Cvrf         EulerCvrf
	Vuln         types.VulnerabilityDetail
	AffectedPkgs []Package
}

type DB interface {
	db.Operation
	Put(tx *bolt.Tx, input PutInput) error
}

type VulnSrc struct {
	DB
	logger *log.Logger
}

type Euler struct {
	db.Operation
}

func NewVulnSrc() *VulnSrc {
	return &VulnSrc{
		DB:     &Euler{Operation: db.Config{}},
		logger: log.WithPrefix("openeuler"),
	}
}

func (vs *VulnSrc) Name() types.SourceID {
	return source.ID
}

func (vs *VulnSrc) Update(dir string) error {
	vs.logger.Info("Saving openEuler CVRF")
	var cvrfs []EulerCvrf
	rootDir := filepath.Join(dir, "vuln-list", eulerDir)
	eb := oops.In("openeuler").With("root_dir", rootDir)

	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var cvrf EulerCvrf
		if err := json.NewDecoder(r).Decode(&cvrf); err != nil {
			return eb.With("file_path", path).Wrapf(err, "json decode error")
		}
		cvrfs = append(cvrfs, cvrf)
		return nil
	})
	if err != nil {
		return eb.Wrapf(err, "openEuler CVRF walk error")
	}

	if err = vs.save(cvrfs); err != nil {
		return eb.Wrapf(err, "openEuler CVRF save error")
	}

	return nil
}

func (vs *VulnSrc) save(cvrfs []EulerCvrf) error {
	err := vs.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, cvrfs)
	})
	if err != nil {
		return oops.Wrapf(err, "batch update error")
	}
	return nil
}

func (vs *VulnSrc) commit(tx *bolt.Tx, cvrfs []EulerCvrf) error {
	var uniqOSVers = make(map[string]struct{})
	for _, cvrf := range cvrfs {
		affectedPkgs := vs.getAffectedPackages(cvrf.ProductTree)
		if len(affectedPkgs) == 0 {
			continue
		}

		for _, pkg := range affectedPkgs {
			advisory := types.Advisory{
				FixedVersion: pkg.FixedVersion,
				Arches:       pkg.Arches,
			}
			// Don't put the same data source multiple times.
			if _, ok := uniqOSVers[pkg.OSVer]; !ok {
				uniqOSVers[pkg.OSVer] = struct{}{}
				if err := vs.PutDataSource(tx, pkg.OSVer, source); err != nil {
					return oops.Wrapf(err, "failed to put data source")
				}
			}

			if err := vs.PutAdvisoryDetail(tx, cvrf.Tracking.ID, pkg.Name,
				[]string{pkg.OSVer}, advisory); err != nil {
				return oops.Wrapf(err, "unable to save %s CVRF", pkg.OSVer)
			}
		}

		var references []string
		for _, ref := range cvrf.References {
			references = append(references, ref.URL)
		}

		severity := types.SeverityUnknown
		for _, cvuln := range cvrf.Vulnerabilities {
			for _, threat := range cvuln.Threats {
				sev := severityFromThreat(threat.Severity)
				if severity < sev {
					severity = sev
				}
			}
		}

		input := PutInput{
			Cvrf: cvrf,
			Vuln: types.VulnerabilityDetail{
				References:  references,
				Title:       cvrf.Title,
				Description: getDetail(cvrf.Notes),
				Severity:    severity,
			},
			AffectedPkgs: affectedPkgs,
		}

		if err := vs.Put(tx, input); err != nil {
			return oops.Wrapf(err, "Put error")
		}
	}
	return nil
}

func (vs *Euler) Put(tx *bolt.Tx, input PutInput) error {
	if err := vs.PutVulnerabilityDetail(tx, input.Cvrf.Tracking.ID, source.ID, input.Vuln); err != nil {
		return oops.With("tracking_id", input.Cvrf.Tracking.ID).Wrapf(err, "failed to save openEuler vulnerability")
	}

	// for optimization
	if err := vs.PutVulnerabilityID(tx, input.Cvrf.Tracking.ID); err != nil {
		return oops.With("tracking_id", input.Cvrf.Tracking.ID).Wrapf(err, "failed to save the vulnerability ID")
	}

	return nil
}

func (vs *VulnSrc) getAffectedPackages(productTree ProductTree) []Package {
	var pkgs []Package
	var osArches = make(map[string][]string) // OS version => arches
	for _, branch := range productTree.Branches {
		// `src` pkgs are the really affected pkgs.
		if branch.Type != "Package Arch" || branch.Name == "" {
			continue
		}
		for _, production := range branch.Productions {
			osVer := vs.getOSVersion(production.CPE)
			if osVer == "" {
				vs.logger.Warn("Unable to parse OS version", log.String("version", production.CPE))
				continue
			}

			// Store possible architectures for OS version.
			// We need this to find affected architectures for src pkg later.
			if branch.Name != "src" {
				if arches, ok := osArches[osVer]; ok {
					osArches[osVer] = append(arches, branch.Name)
				} else {
					osArches[osVer] = []string{branch.Name}
				}
				continue
			}

			// e.g., `ignition-2.14.0-2` or `ignition-2.14.0-2.oe2203sp2.src.rpm`
			pkgName, pkgVersion := parseProduction(production)
			if pkgName == "" || pkgVersion == "" {
				vs.logger.Warn("Unable to parse Production", log.String("production", production.ProductID))
				continue
			}
			pkg := Package{
				Name:         pkgName,
				FixedVersion: pkgVersion,
				OSVer:        osVer,
			}
			pkgs = append(pkgs, pkg)
		}
	}

	// Fill affected architectures
	for i, pkg := range pkgs {
		arches := lo.Uniq(osArches[pkg.OSVer])
		sort.Strings(arches)
		pkgs[i].Arches = arches
	}

	return pkgs
}

func (vs *VulnSrc) getOSVersion(cpe string) string {
	// e.g. cpe:/a:openEuler:openEuler:22.03-LTS-SP3
	parts := strings.Split(cpe, ":")
	// Wrong CPE format
	if len(parts) < 4 || len(parts) > 5 || parts[2] != "openEuler" {
		return ""
	}

	// There are 2 separators between OS name and version: `:` (default) and `-` (There are several cases).
	// e.g. cpe:/a:openEuler:openEuler:22.03-LTS-SP3 and
	var version string
	if len(parts) == 5 { // e.g. `cpe:/a:openEuler:openEuler:22.03-LTS-SP3` => `22.03-LTS-SP3`
		version = parts[4]
	} else { // e.g. `cpe:/a:openEuler:openEuler-22.03-LTS` => `openEuler-22.03-LTS` => `22.03-LTS`
		if osName, ver, ok := strings.Cut(parts[3], "-"); ok && osName == "openEuler" {
			version = ver
		}
	}

	// There are cases when different `SP<X>` OSes have different fixed versions
	// see https://github.com/aquasecurity/trivy-db/pull/397#discussion_r1680608109
	// So we need to keep the full version (with `LTS` and `SPX` suffixes)
	if len(strings.Split(version, "-")) > 3 || version == "" {
		vs.logger.Warn("Invalid openEuler version", log.String("version", version))
		return ""
	}
	return fmt.Sprintf(openEulerFormat, version)
}

func getDetail(notes []DocumentNote) string {
	for _, n := range notes {
		if n.Type == "General" && n.Title == "Description" {
			return n.Text
		}
	}
	return ""
}

func parseProduction(production Production) (string, string) {
	name, version := splitPkgName(production.ProductID)
	if name == "" || version == "" {
		text, _, _ := strings.Cut(production.Text, ".oe")
		name, version = splitPkgName(text)
	}
	return name, version
}

func splitPkgName(product string) (string, string) {
	// Trim release
	index := strings.LastIndex(product, "-")
	if index == -1 {
		return "", ""
	}

	release := product[index:]
	nameWithVersion := product[:index]

	// Trim version
	index = strings.LastIndex(nameWithVersion, "-")
	if index == -1 {
		return "", ""
	}
	version := nameWithVersion[index+1:] + release
	name := nameWithVersion[:index]

	return name, version
}

func (vs VulnSrc) Get(version, pkgName, arch string) ([]types.Advisory, error) {
	eb := oops.In("openeuler").With("version", version).With("package_name", pkgName)
	bucket := fmt.Sprintf(openEulerFormat, version)
	advisories, err := vs.GetAdvisories(bucket, pkgName)

	if err != nil {
		return nil, eb.Wrapf(err, "failed to get openEuler advisories")
	}

	// Filter advisories by arch
	advisories = lo.Filter(advisories, func(adv types.Advisory, _ int) bool {
		return slices.Contains(adv.Arches, arch)
	})

	if len(advisories) == 0 {
		return nil, nil
	}
	return advisories, nil
}

func severityFromThreat(sev string) types.Severity {
	switch sev {
	case "Low":
		return types.SeverityLow
	case "Medium":
		return types.SeverityMedium
	case "High":
		return types.SeverityHigh
	case "Critical":
		return types.SeverityCritical
	}
	return types.SeverityUnknown
}
