package alma

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
	version "github.com/knqyf263/go-rpm-version"
)

const (
	almaDir = "alma"
)

var (
	platformFormat = "alma %s"

	source = types.DataSource{
		ID:   vulnerability.Alma,
		Name: "AlmaLinux Product Errata",
		URL:  "https://errata.almalinux.org/",
	}
)

type PutInput struct {
	platformName string
	cveID        string
	vuln         types.VulnerabilityDetail
	advisories   map[string]types.Advisory
	erratum      Erratum // for extensibility
}

type DB interface {
	db.Operation
	Put(*bolt.Tx, PutInput) error
	Get(release, pkgName string) ([]types.Advisory, error)
}

type VulnSrc struct {
	db DB // Those who want to customize Trivy DB can override put/get methods.
}

// Alma implements the DB interface
type Alma struct {
	db.Operation
}

func NewVulnSrc() *VulnSrc {
	return &VulnSrc{
		db: &Alma{Operation: db.Config{}},
	}
}

func (vs *VulnSrc) Name() types.SourceID {
	return source.ID
}

func (vs *VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", almaDir)
	errata, err := vs.parse(rootDir)
	if err != nil {
		return err
	}
	if err = vs.put(errata); err != nil {
		return xerrors.Errorf("error in Alma save: %w", err)
	}

	return nil
}

// parse parses all the advisories from Alma Linux.
func (vs *VulnSrc) parse(rootDir string) (map[string][]Erratum, error) {
	errata := map[string][]Erratum{}
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var erratum Erratum
		if err := json.NewDecoder(r).Decode(&erratum); err != nil {
			return xerrors.Errorf("failed to decode Alma erratum: %w", err)
		}

		dirs := strings.Split(path, string(filepath.Separator))
		if len(dirs) < 3 {
			log.Printf("invalid path: %s\n", path)
			return nil
		}

		majorVer := dirs[len(dirs)-3]
		errata[majorVer] = append(errata[majorVer], erratum)
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("error in Alma walk: %w", err)
	}

	return errata, nil
}

func (vs *VulnSrc) put(errataVer map[string][]Erratum) error {
	err := vs.db.BatchUpdate(func(tx *bolt.Tx) error {
		for majorVer, errata := range errataVer {
			platformName := fmt.Sprintf(platformFormat, majorVer)
			if err := vs.db.PutDataSource(tx, platformName, source); err != nil {
				return xerrors.Errorf("failed to put data source: %w", err)
			}

			if err := vs.commit(tx, platformName, errata); err != nil {
				return xerrors.Errorf("Alma %s commit error: %w", majorVer, err)
			}
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in db batch update: %w", err)
	}
	return nil
}

func (vs *VulnSrc) commit(tx *bolt.Tx, platformName string, errata []Erratum) error {
	for _, erratum := range errata {
		var references []string
		for _, ref := range erratum.References {
			if ref.Type != "cve" {
				references = append(references, ref.Href)
			}
		}

		for _, ref := range erratum.References {
			if ref.Type != "cve" {
				continue
			}

			// We need to work around this issue for now.
			// https://github.com/aquasecurity/fanal/issues/186#issuecomment-931523102
			advisories := map[string]types.Advisory{}

			cveID := ref.ID
			for _, pkg := range erratum.Pkglist.Packages {
				if pkg.Arch != "noarch" && pkg.Arch != "x86_64" {
					continue
				}

				pkgName := pkg.Name
				if erratum.Pkglist.Module.Name != "" && erratum.Pkglist.Module.Stream != "" {
					pkgName = fmt.Sprintf("%s:%s::%s", erratum.Pkglist.Module.Name, erratum.Pkglist.Module.Stream, pkg.Name)
				}

				advisory := types.Advisory{
					FixedVersion: utils.ConstructVersion(pkg.Epoch, pkg.Version, pkg.Release),
				}

				if adv, ok := advisories[pkgName]; ok {
					if version.NewVersion(advisory.FixedVersion).LessThan(version.NewVersion(adv.FixedVersion)) {
						advisories[pkgName] = advisory
					}
				} else {
					advisories[pkgName] = advisory
				}
			}

			vuln := types.VulnerabilityDetail{
				Severity:    generalizeSeverity(erratum.Severity),
				Title:       erratum.Title,
				Description: erratum.Description,
				References:  references,
			}

			err := vs.db.Put(tx, PutInput{
				platformName: platformName,
				cveID:        cveID,
				vuln:         vuln,
				advisories:   advisories,
				erratum:      erratum,
			})
			if err != nil {
				return xerrors.Errorf("db put error: %w", err)
			}
		}
	}
	return nil
}

func (a *Alma) Put(tx *bolt.Tx, input PutInput) error {
	if err := a.PutVulnerabilityDetail(tx, input.cveID, source.ID, input.vuln); err != nil {
		return xerrors.Errorf("failed to save Alma vulnerability: %w", err)
	}

	if err := a.PutVulnerabilityID(tx, input.cveID); err != nil {
		return xerrors.Errorf("failed to save the vulnerability ID: %w", err)
	}

	for pkgName, advisory := range input.advisories {
		if err := a.PutAdvisoryDetail(tx, input.cveID, pkgName, []string{input.platformName}, advisory); err != nil {
			return xerrors.Errorf("failed to save Alma advisory: %w", err)
		}
	}
	return nil
}

func (a *Alma) Get(release, pkgName string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, release)
	advisories, err := a.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get Alma advisories: %w", err)
	}
	return advisories, nil
}

func generalizeSeverity(severity string) types.Severity {
	switch strings.ToLower(severity) {
	case "low":
		return types.SeverityLow
	case "moderate":
		return types.SeverityMedium
	case "important":
		return types.SeverityHigh
	case "critical":
		return types.SeverityCritical
	}
	return types.SeverityUnknown
}
