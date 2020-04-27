package amazon

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/types"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/vuln-list-update/amazon"
)

const (
	amazonDir      = "amazon"
	platformFormat = "amazon linux %s"
)

var (
	targetVersions = []string{"1", "2"}
	fileWalker     = utils.FileWalk // TODO: Remove once utils.go exposes an interface
)

type VulnSrc struct {
	dbc      db.Operation
	alasList []alas
}

type alas struct {
	Version string
	amazon.ALAS
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", amazonDir)

	err := fileWalker(rootDir, vs.walkFunc)
	if err != nil {
		return xerrors.Errorf("error in amazon walk: %w", err)
	}

	if err = vs.save(); err != nil {
		return xerrors.Errorf("error in amazon save: %w", err)
	}

	return nil
}

func (vs *VulnSrc) walkFunc(r io.Reader, path string) error {
	paths := strings.Split(path, string(filepath.Separator))
	if len(paths) < 2 {
		return nil
	}
	version := paths[len(paths)-2]
	if !utils.StringInSlice(version, targetVersions) {
		log.Printf("unsupported amazon version: %s\n", version)
		return nil
	}

	var vuln amazon.ALAS
	if err := json.NewDecoder(r).Decode(&vuln); err != nil {
		return xerrors.Errorf("failed to decode amazon JSON: %w", err)
	}

	vs.alasList = append(vs.alasList, alas{
		Version: version,
		ALAS:    vuln,
	})
	return nil
}

func (vs VulnSrc) save() error {
	log.Println("Saving amazon DB")
	err := vs.dbc.BatchUpdate(vs.commit())
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}
	return nil
}

// TODO: Cleanup the double layer of nested closures
func (vs VulnSrc) commit() func(tx *bolt.Tx) error {
	return vs.commitFunc
}

func (vs VulnSrc) commitFunc(tx *bolt.Tx) error {
	for _, alas := range vs.alasList {
		for _, cveID := range alas.CveIDs {
			for _, pkg := range alas.Packages {
				platformName := fmt.Sprintf(platformFormat, alas.Version)
				advisory := types.Advisory{
					FixedVersion: constructVersion(pkg.Epoch, pkg.Version, pkg.Release),
				}
				if err := vs.dbc.PutAdvisory(tx, platformName, pkg.Name, cveID, advisory); err != nil {
					return xerrors.Errorf("failed to save amazon advisory: %w", err)
				}

				var references []string
				for _, ref := range alas.References {
					references = append(references, ref.Href)
				}

				vuln := types.VulnerabilityDetail{
					Severity:    severityFromPriority(alas.Severity),
					References:  references,
					Description: alas.Description,
					Title:       "",
				}
				if err := vs.dbc.PutVulnerabilityDetail(tx, cveID, vulnerability.Amazon, vuln); err != nil {
					return xerrors.Errorf("failed to save amazon vulnerability detail: %w", err)
				}

				// for light DB
				if err := vs.dbc.PutSeverity(tx, cveID, types.SeverityUnknown); err != nil {
					return xerrors.Errorf("failed to save alpine vulnerability severity: %w", err)
				}
			}
		}
	}
	return nil
}

// Get returns a security advisory
func (vs VulnSrc) Get(version string, pkgName string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, version)
	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get Amazon advisories: %w", err)
	}
	return advisories, nil
}

func severityFromPriority(priority string) types.Severity {
	switch priority {
	case "low":
		return types.SeverityLow
	case "medium":
		return types.SeverityMedium
	case "important":
		return types.SeverityHigh
	case "critical":
		return types.SeverityCritical
	default:
		return types.SeverityUnknown
	}
}

func constructVersion(epoch, version, release string) string {
	verStr := ""
	if epoch != "0" && epoch != "" {
		verStr += fmt.Sprintf("%s:", epoch)
	}
	verStr += version

	if release != "" {
		verStr += fmt.Sprintf("-%s", release)

	}
	return verStr
}
