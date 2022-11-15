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

type Option func(src *VulnSrc)

func WithCustomPut(put db.CustomPut) Option {
	return func(src *VulnSrc) {
		src.put = put
	}
}

func WithDB(db db.Operation) Option {
	return func(src *VulnSrc) {
		src.dbc = db
	}
}

type VulnSrc struct {
	put db.CustomPut
	dbc db.Operation
}

func NewVulnSrc(opts ...Option) VulnSrc {
	src := VulnSrc{
		put: defaultPut,
		dbc: db.Config{},
	}

	for _, o := range opts {
		o(&src)
	}

	return src
}

func (vs VulnSrc) Name() types.SourceID {
	return source.ID
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", almaDir)
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
		return xerrors.Errorf("error in Alma walk: %w", err)
	}

	if err = vs.save(errata); err != nil {
		return xerrors.Errorf("error in Alma save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(errataVer map[string][]Erratum) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		err := vs.commit(tx, errataVer)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in db batch update: %w", err)
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, errataVer map[string][]Erratum) error {
	if err := vs.put(vs.dbc, tx, errataVer); err != nil {
		return xerrors.Errorf("put error: %w", err)
	}
	return nil
}

func defaultPut(dbi interface{}, tx *bolt.Tx, advisory interface{}) error {
	dbc := dbi.(db.Config)
	Erratum, ok := advisory.(map[string][]Erratum)
	if !ok {
		return xerrors.New("unknown type")
	}
	for majorVer, errata := range Erratum {
		platformName := fmt.Sprintf(platformFormat, majorVer)
		if err := dbc.PutDataSource(tx, platformName, source); err != nil {
			return xerrors.Errorf("failed to put data source: %w", err)
		}

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

					dbAdvisory := types.Advisory{
						FixedVersion: utils.ConstructVersion(pkg.Epoch, pkg.Version, pkg.Release),
					}

					if adv, ok := advisories[pkgName]; ok {
						if version.NewVersion(dbAdvisory.FixedVersion).LessThan(version.NewVersion(adv.FixedVersion)) {
							advisories[pkgName] = dbAdvisory
						}
					} else {
						advisories[pkgName] = dbAdvisory
					}

					vuln := types.VulnerabilityDetail{
						Severity:    generalizeSeverity(erratum.Severity),
						Title:       erratum.Title,
						Description: erratum.Description,
						References:  references,
					}
					if err := dbc.PutVulnerabilityDetail(tx, cveID, source.ID, vuln); err != nil {
						return xerrors.Errorf("failed to save Alma vulnerability: %w", err)
					}

					if err := dbc.PutVulnerabilityID(tx, cveID); err != nil {
						return xerrors.Errorf("failed to save the vulnerability ID: %w", err)
					}
				}

				for pkgName, advisory := range advisories {
					if err := dbc.PutAdvisoryDetail(tx, cveID, pkgName, []string{platformName}, advisory); err != nil {
						return xerrors.Errorf("failed to save Alma advisory: %w", err)
					}
				}
			}
		}
	}
	return nil
}

func (vs VulnSrc) Get(release, pkgName string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, release)
	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
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
