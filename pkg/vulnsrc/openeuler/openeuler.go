package openeuler

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
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
	log.Println("Saving openEuler CVRF")
	var cvrfs []Cvrf
	rootDir := filepath.Join(dir, "vuln-list", eulerDir)
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var cvrf Cvrf
		if err := json.NewDecoder(r).Decode(&cvrf); err != nil {
			return xerrors.Errorf("failed to decode openEuler CVRF JSON: %w %+v", err, cvrf)
		}
		cvrfs = append(cvrfs, cvrf)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in openEuler CVRF walk: %w", err)
	}

	if err = vs.save(cvrfs); err != nil {
		return xerrors.Errorf("error in openEuler CVRF save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(cvrfs []Cvrf) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, cvrfs)
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, cvrfs []Cvrf) error {
	for _, cvrf := range cvrfs {
		affectedPkgs := getAffectedPackages(cvrf.ProductTree)
		if len(affectedPkgs) == 0 {
			continue
		}

		for pkg, arches := range affectedPkgs {
			advisory := types.Advisory{
				FixedVersion: pkg.FixedVersion,
				Arches:       arches,
			}
			if err := vs.dbc.PutDataSource(tx, pkg.OSVer, source); err != nil {
				return xerrors.Errorf("failed to put data source: %w", err)
			}
			if err := vs.dbc.PutAdvisoryDetail(tx, cvrf.Tracking.ID, pkg.Name,
				[]string{pkg.OSVer}, advisory); err != nil {
				return xerrors.Errorf("unable to save %s CVRF: %w", pkg.OSVer, err)
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

		vuln := types.VulnerabilityDetail{
			References:  references,
			Title:       cvrf.Title,
			Description: getDetail(cvrf.Notes),
			Severity:    severity,
		}
		if err := vs.dbc.PutVulnerabilityDetail(tx, cvrf.Tracking.ID, source.ID, vuln); err != nil {
			return xerrors.Errorf("failed to save openEuler CVRF vulnerability: %w", err)
		}

		// for optimization
		if err := vs.dbc.PutVulnerabilityID(tx, cvrf.Tracking.ID); err != nil {
			return xerrors.Errorf("failed to save the vulnerability ID: %w", err)
		}
	}
	return nil
}

func getAffectedPackages(productTree ProductTree) AffectedPackages {
	pkgs := AffectedPackages{}
	for _, branch := range productTree.Branches {
		// `src` pkgs are not installed in openEuler.
		if branch.Type != "Package Arch" || branch.Name == "src" {
			continue
		}
		for _, production := range branch.Productions {
			osVer := getOSVersion(production.CPE)
			if osVer == "" {
				continue
			}

			// e.g., ignition-debuginfo-2.14.0-2
			pkg := getPackage(production.ProductID, osVer)
			if pkg == nil {
				// productID and FixVersion are also always contained
				// in `production.Text`.
				parts := strings.Split(production.Text, ".oe")
				pkg = getPackage(parts[0], osVer)
			}
			pkgs[*pkg] = append(pkgs[*pkg], branch.Name)
		}
	}
	return pkgs
}

func getOSVersion(cpe string) string {
	// e.g. cpe:/a:openEuler:openEuler:22.03-LTS-SP3
	parts := strings.Split(cpe, ":")
	if len(parts) != 5 || parts[2] != "openEuler" {
		return ""
	}
	version := parts[4]
	// e.g. 23.09, 22.03-LTS, 22.03-LTS-SP3
	if len(strings.Split(version, "-")) > 3 {
		log.Printf("invalid openEuler version: %s", version)
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

func getPackage(product string, osVer string) *Package {
	name, version := splitPkgName(product)
	if name == "" || version == "" {
		return nil
	}
	return &Package{
		Name:         name,
		OSVer:        osVer,
		FixedVersion: version,
	}
}

func splitPkgName(product string) (string, string) {
	// Trim release
	index := strings.LastIndex(product, "-")
	if index == -1 {
		return "", ""
	}

	release := product[index:]
	pkgWithVersion := product[:index]

	// Trim version
	index = strings.LastIndex(pkgWithVersion, "-")
	if index == -1 {
		return "", ""
	}
	version := pkgWithVersion[index+1:] + release
	name := pkgWithVersion[:index]

	return name, version
}

func (vs VulnSrc) Get(version string, pkgName string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(openEulerFormat, version)
	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get openEuler advisories: %w", err)
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
