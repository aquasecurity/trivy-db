package alma

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	version "github.com/knqyf263/go-rpm-version"
	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
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
	PlatformName string
	CveID        string
	Vuln         types.VulnerabilityDetail
	Advisories   map[string]types.Advisory
	Erratum      Erratum // for extensibility, not used in trivy-db
}

type DB interface {
	db.Operation
	db.Getter
	Put(*bolt.Tx, PutInput) error
}

type VulnSrc struct {
	DB     // Those who want to customize Trivy DB can override put/get methods.
	logger *log.Logger
}

// Alma implements the DB interface
type Alma struct {
	db.Operation
}

func NewVulnSrc() *VulnSrc {
	return &VulnSrc{
		DB:     &Alma{Operation: db.Config{}},
		logger: log.WithPrefix("alma"),
	}
}

func (vs *VulnSrc) Name() types.SourceID {
	return source.ID
}

func (vs *VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", almaDir)
	eb := oops.In("alma").With("root_dir", rootDir)

	errata, err := vs.parse(rootDir)
	if err != nil {
		return eb.Wrap(err)
	}
	if err = vs.put(errata); err != nil {
		return eb.Wrapf(err, "put error")
	}

	return nil
}

// parse parses all the advisories from Alma Linux.
func (vs *VulnSrc) parse(rootDir string) (map[string][]Erratum, error) {
	errata := map[string][]Erratum{}
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		eb := oops.With("file_path", path)

		var erratum Erratum
		if err := json.NewDecoder(r).Decode(&erratum); err != nil {
			return eb.Wrapf(err, "json decode error")
		}

		dirs := strings.Split(path, string(filepath.Separator))
		if len(dirs) < 3 {
			vs.logger.Warn("Invalid path", log.FilePath(path))
			return nil
		}

		majorVer := dirs[len(dirs)-3]
		errata[majorVer] = append(errata[majorVer], erratum)
		return nil
	})
	if err != nil {
		return nil, oops.Wrapf(err, "walk error")
	}

	return errata, nil
}

func (vs *VulnSrc) put(errataVer map[string][]Erratum) error {
	err := vs.BatchUpdate(func(tx *bolt.Tx) error {
		for majorVer, errata := range errataVer {
			platformName := fmt.Sprintf(platformFormat, majorVer)
			eb := oops.With("platform", platformName).With("major_version", majorVer)
			if err := vs.PutDataSource(tx, platformName, source); err != nil {
				return eb.Wrapf(err, "failed to put data source")
			}

			if err := vs.commit(tx, platformName, errata); err != nil {
				return eb.Wrapf(err, "commit error")
			}
		}
		return nil
	})
	if err != nil {
		return oops.Wrapf(err, "db batch update error")
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

			err := vs.Put(tx, PutInput{
				PlatformName: platformName,
				CveID:        cveID,
				Vuln:         vuln,
				Advisories:   advisories,
				Erratum:      erratum,
			})
			if err != nil {
				return oops.With("vuln_id", cveID).With("platform", platformName).Wrapf(err, "db put error")
			}
		}
	}
	return nil
}

func (a *Alma) Put(tx *bolt.Tx, input PutInput) error {
	if err := a.PutVulnerabilityDetail(tx, input.CveID, source.ID, input.Vuln); err != nil {
		return oops.Wrapf(err, "failed to save vulnerability detail")
	}

	// for optimization
	if err := a.PutVulnerabilityID(tx, input.CveID); err != nil {
		return oops.Wrapf(err, "failed to save vulnerability ID")
	}

	for pkgName, advisory := range input.Advisories {
		if err := a.PutAdvisoryDetail(tx, input.CveID, pkgName, []string{input.PlatformName}, advisory); err != nil {
			return oops.Wrapf(err, "failed to save advisory")
		}
	}
	return nil
}

func (a *Alma) Get(params db.GetParams) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, params.Release)
	advisories, err := a.GetAdvisories(bucket, params.PkgName)
	if err != nil {
		return nil, oops.With("release", params.Release).With("package_name", params.PkgName).Wrapf(err, "failed to get advisories")
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
