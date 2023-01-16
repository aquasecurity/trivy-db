package rocky

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
	ustrings "github.com/aquasecurity/trivy-db/pkg/utils/strings"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	rockyDir       = "rocky"
	platformFormat = "rocky %s"
)

var (
	targetRepos  = []string{"BaseOS", "AppStream", "extras"}
	targetArches = []string{"x86_64"}
	source       = types.DataSource{
		ID:   vulnerability.Rocky,
		Name: "Rocky Linux updateinfo",
		URL:  "https://download.rockylinux.org/pub/rocky/",
	}
)

type PutInput struct {
	PlatformName string
	CveID        string
	Vuln         types.VulnerabilityDetail
	Advisories   map[string]types.Advisory // pkg name => advisory
	Erratum      RLSA                      // for extensibility, not used in trivy-db
}

type DB interface {
	db.Operation
	Put(*bolt.Tx, PutInput) error
	Get(release, pkgName string) ([]types.Advisory, error)
}

type VulnSrc struct {
	DB
}

type Rocky struct {
	db.Operation
}

func NewVulnSrc() *VulnSrc {
	return &VulnSrc{
		DB: &Rocky{Operation: db.Config{}},
	}
}

func (vs *VulnSrc) Name() types.SourceID {
	return source.ID
}

func (vs *VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", rockyDir)
	errata, err := vs.parse(rootDir)
	if err != nil {
		return err
	}
	if err = vs.put(errata); err != nil {
		return xerrors.Errorf("error in Rocky save: %w", err)
	}

	return nil
}

// parse parses all the advisories from Rocky Linux.
// It is exported for those who want to customize trivy-db.
func (vs *VulnSrc) parse(rootDir string) (map[string][]RLSA, error) {
	errata := map[string][]RLSA{}
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var erratum RLSA
		if err := json.NewDecoder(r).Decode(&erratum); err != nil {
			return xerrors.Errorf("failed to decode Rocky erratum: %w", err)
		}

		dirs := strings.Split(strings.TrimPrefix(path, rootDir), string(filepath.Separator))[1:]
		if len(dirs) != 5 {
			log.Printf("Invalid path: %s", path)
			return nil
		}

		// vulnerabilities are contained in directories with a minor version(like 8.5)
		majorVer := dirs[0]
		if strings.Count(dirs[0], ".") > 0 {
			majorVer = dirs[0][:strings.Index(dirs[0], ".")]
		}
		repo, arch := dirs[1], dirs[2]
		if !ustrings.InSlice(repo, targetRepos) {
			log.Printf("Unsupported Rocky repo: %s", repo)
			return nil
		}

		if !ustrings.InSlice(arch, targetArches) {
			switch arch {
			case "aarch64":
			default:
				log.Printf("Unsupported Rocky arch: %s", arch)
			}
			return nil
		}

		errata[majorVer] = append(errata[majorVer], erratum)
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("error in Rocky walk: %w", err)
	}
	return errata, nil
}

func (vs *VulnSrc) put(errataVer map[string][]RLSA) error {
	err := vs.BatchUpdate(func(tx *bolt.Tx) error {
		for majorVer, errata := range errataVer {
			platformName := fmt.Sprintf(platformFormat, majorVer)
			if err := vs.PutDataSource(tx, platformName, source); err != nil {
				return xerrors.Errorf("failed to put data source: %w", err)
			}
			if err := vs.commit(tx, platformName, errata); err != nil {
				return xerrors.Errorf("error in save Rocky %s: %w", majorVer, err)
			}
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in db batch update: %w", err)
	}
	return nil
}

func (vs *VulnSrc) commit(tx *bolt.Tx, platformName string, errata []RLSA) error {
	for _, erratum := range errata {
		for _, cveID := range erratum.CveIDs {
			advisories := map[string]types.Advisory{}
			for _, pkg := range erratum.Packages {
				// Skip the modular packages until the following bug is fixed.
				// https://forums.rockylinux.org/t/some-errata-missing-in-comparison-with-rhel-and-almalinux/3843/8
				if strings.Contains(pkg.Release, ".module+el") {
					continue
				}

				advisories[pkg.Name] = types.Advisory{
					FixedVersion: utils.ConstructVersion(pkg.Epoch, pkg.Version, pkg.Release),
				}
			}

			if len(advisories) == 0 {
				continue
			}

			var references []string
			for _, ref := range erratum.References {
				references = append(references, ref.Href)
			}

			vuln := types.VulnerabilityDetail{
				Severity:    generalizeSeverity(erratum.Severity),
				References:  references,
				Title:       erratum.Title,
				Description: erratum.Description,
			}

			err := vs.Put(tx, PutInput{
				PlatformName: platformName,
				CveID:        cveID,
				Vuln:         vuln,
				Advisories:   advisories,
				Erratum:      erratum,
			})
			if err != nil {
				return xerrors.Errorf("db put error: %w", err)
			}
		}
	}
	return nil
}

func (r *Rocky) Put(tx *bolt.Tx, input PutInput) error {
	if err := r.PutVulnerabilityDetail(tx, input.CveID, source.ID, input.Vuln); err != nil {
		return xerrors.Errorf("failed to save Rocky vulnerability: %w", err)
	}

	// for optimization
	if err := r.PutVulnerabilityID(tx, input.CveID); err != nil {
		return xerrors.Errorf("failed to save the vulnerability ID: %w", err)
	}

	for pkgName, advisory := range input.Advisories {
		if err := r.PutAdvisoryDetail(tx, input.CveID, pkgName, []string{input.PlatformName}, advisory); err != nil {
			return xerrors.Errorf("failed to save Rocky advisory: %w", err)
		}
	}
	return nil
}

func (r *Rocky) Get(release, pkgName string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, release)
	advisories, err := r.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get Rocky advisories: %w", err)
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
