package photonoval

import (
	"encoding/json"
	"io"
	"path/filepath"
	"strings"

	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const photonOvalDir = "photon-oval"

var source = types.DataSource{
	ID:   vulnerability.PhotonOVAL,
	Name: "Photon OS OVAL definitions",
	URL:  "https://packages.broadcom.com/photon/photon_oval/",
}

// VulnSrc implements the VulnSrc interface for Photon OS OVAL advisories
type VulnSrc struct {
	dbc    db.Operation
	logger *log.Logger
}

// NewVulnSrc returns a new VulnSrc for Photon OS OVAL
func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc:    db.Config{},
		logger: log.WithPrefix("photon-oval"),
	}
}

// Name returns the source ID
func (vs VulnSrc) Name() types.SourceID {
	return source.ID
}

// Update walks the photon/oval directory tree and stores all advisories to BoltDB
func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", photonOvalDir)
	eb := oops.In("photon-oval").With("root_dir", rootDir)

	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		// Extract OS version from path segment, e.g. ".../photon/oval/5.0/PHSA-....json" -> "5.0"
		osVer, err := osVersionFromPath(rootDir, path)
		if err != nil {
			return eb.With("file_path", path).Wrapf(err, "failed to extract OS version from path")
		}

		var oval PhotonOVAL
		if err = json.NewDecoder(r).Decode(&oval); err != nil {
			return eb.With("file_path", path).Wrapf(err, "json decode error")
		}

		if err = vs.save(osVer, oval); err != nil {
			return eb.With("file_path", path).Wrapf(err, "save error")
		}
		return nil
	})
	if err != nil {
		return eb.Wrapf(err, "walk error")
	}
	return nil
}

// osVersionFromPath extracts the OS version segment from the file path.
// Given rootDir = ".../photon/oval" and path = ".../photon/oval/5.0/PHSA-2023-0001.json",
// the function returns "5.0".
func osVersionFromPath(rootDir, path string) (string, error) {
	rel, err := filepath.Rel(rootDir, path)
	if err != nil {
		return "", err
	}
	// rel is like "5.0/PHSA-2023-0001.json"
	parts := strings.SplitN(rel, string(filepath.Separator), 2)
	if len(parts) < 2 {
		return "", oops.Errorf("unexpected path structure: %s", path)
	}
	return parts[0], nil
}

func (vs VulnSrc) save(osVer string, oval PhotonOVAL) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, osVer, oval)
	})
	if err != nil {
		return oops.Wrapf(err, "batch update error")
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, osVer string, oval PhotonOVAL) error {
	platform := platformName(osVer)

	if err := vs.dbc.PutDataSource(tx, platform, source); err != nil {
		return oops.With("platform", platform).Wrapf(err, "failed to put data source")
	}

	pkgs := parsePackages(oval.Criteria)
	if len(pkgs) == 0 {
		return nil
	}

	sev := mapSeverity(oval.Severity)

	for _, cve := range oval.Cves {
		if cve.ID == "" {
			continue
		}

		vuln := types.VulnerabilityDetail{
			Severity: sev,
		}
		if err := vs.dbc.PutVulnerabilityDetail(tx, cve.ID, source.ID, vuln); err != nil {
			return oops.With("cve_id", cve.ID).Wrapf(err, "failed to save vulnerability detail")
		}

		if err := vs.dbc.PutVulnerabilityID(tx, cve.ID); err != nil {
			return oops.With("cve_id", cve.ID).Wrapf(err, "failed to save vulnerability ID")
		}

		for _, pkg := range pkgs {
			advisory := types.Advisory{
				FixedVersion: pkg.FixedVersion,
			}
			if err := vs.dbc.PutAdvisoryDetail(tx, cve.ID, pkg.Name, []string{platform}, advisory); err != nil {
				return oops.With("cve_id", cve.ID).With("pkg", pkg.Name).Wrapf(err, "failed to save advisory")
			}
		}
	}
	return nil
}

// parsePackages walks the Criteria tree and extracts all affected packages with fixed versions.
// It matches criterion comments of the form "{pkg} is earlier than 0:{ver}"
// and skips "is signed with VMware key" lines.
func parsePackages(criteria Criteria) []AffectedPackage {
	var pkgs []AffectedPackage
	for _, c := range criteria.Criterions {
		ss := strings.Split(c.Comment, " is earlier than ")
		if len(ss) != 2 {
			continue
		}
		pkgName := strings.TrimSpace(ss[0])
		rawVer := strings.TrimSpace(ss[1])
		// Strip the leading "0:" epoch prefix if present
		fixedVersion := strings.TrimPrefix(rawVer, "0:")
		pkgs = append(pkgs, AffectedPackage{
			Name:         pkgName,
			FixedVersion: fixedVersion,
		})
	}
	for _, sub := range criteria.Criterias { //nolint:misspell
		pkgs = append(pkgs, parsePackages(sub)...)
	}
	return pkgs
}

// mapSeverity maps a Photon OVAL severity string to a types.Severity value
func mapSeverity(sev string) types.Severity {
	switch sev {
	case "Critical":
		return types.SeverityCritical
	case "Important":
		return types.SeverityHigh
	case "Moderate":
		return types.SeverityMedium
	case "Low":
		return types.SeverityLow
	}
	return types.SeverityUnknown
}

// platformName returns the BoltDB bucket name for a given Photon OS version
func platformName(osVer string) string {
	return bucket.NewPhoton(osVer).Name()
}

// Get returns advisories for a given Photon OS release and package name
func (vs VulnSrc) Get(params db.GetParams) ([]types.Advisory, error) {
	eb := oops.In("photon-oval").With("release", params.Release)
	platform := platformName(params.Release)
	advisories, err := vs.dbc.GetAdvisories(platform, params.PkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get advisories")
	}
	return advisories, nil
}
