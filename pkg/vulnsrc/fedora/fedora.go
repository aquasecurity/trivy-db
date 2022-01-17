package fedora

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
	fedoraDir = "fedora/fedora"
)

var (
	platformFormat   = "fedora %s"
	targetRepository = []string{"Everything", "Modular"}
	targetArches     = []string{"x86_64"}

	source = types.DataSource{
		ID:   vulnerability.Fedora,
		Name: "Fedora UpdateInfo",
		URL:  "https://dl.fedoraproject.org/pub/fedora/linux/updates",
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
	rootDir := filepath.Join(dir, "vuln-list", fedoraDir)
	errata := map[string][]UpdateInfo{}
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var erratum UpdateInfo
		if err := json.NewDecoder(r).Decode(&erratum); err != nil {
			return xerrors.Errorf("failed to decode Fedora erratum: %w", err)
		}

		dirs := strings.Split(strings.TrimPrefix(path, rootDir), string(filepath.Separator))[1:]
		majorVer := dirs[0]
		repo := dirs[1]
		if !ustrings.InSlice(repo, targetRepository) {
			log.Printf("unsupported Fedora Repository: %s\n", repo)
			return nil
		}

		arch := dirs[2]
		if !ustrings.InSlice(arch, targetArches) {
			switch arch {
			case "aarch64":
			default:
				log.Printf("unsupported Fedora arch: %s\n", arch)
			}
			return nil
		}

		errata[majorVer] = append(errata[majorVer], erratum)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in Fedora walk: %w", err)
	}

	if err := vs.save(errata); err != nil {
		return xerrors.Errorf("error in Fedora save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(errataVer map[string][]UpdateInfo) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		for majorVer, errata := range errataVer {
			platformName := fmt.Sprintf(platformFormat, majorVer)
			if err := vs.commit(tx, platformName, errata); err != nil {
				return xerrors.Errorf("error in save Fedora %s: %w", majorVer, err)
			}
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in db batch update: %w", err)
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, platformName string, errata []UpdateInfo) error {
	for _, erratum := range errata {
		for _, cveID := range erratum.CveIDs {
			for _, pkg := range erratum.Packages {
				advisory := types.Advisory{
					FixedVersion: constructVersion(pkg.Epoch, pkg.Version, pkg.Release),
				}

				pkgName := pkg.Name
				if erratum.Module.Name != "" && erratum.Module.Stream != "" {
					pkgName = fmt.Sprintf("%s:%s::%s", erratum.Module.Name, erratum.Module.Stream, pkg.Name)
				}

				if err := vs.dbc.PutAdvisoryDetail(tx, cveID, pkgName, []string{platformName}, advisory); err != nil {
					return xerrors.Errorf("failed to save Fedora advisory: %w", err)
				}

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
			if err := vs.dbc.PutVulnerabilityDetail(tx, cveID, vulnerability.Fedora, vuln); err != nil {
				return xerrors.Errorf("failed to save Fedora vulnerability: %w", err)
			}

			if err := vs.dbc.PutVulnerabilityID(tx, cveID); err != nil {
				return xerrors.Errorf("failed to save the vulnerability ID: %w", err)
			}
		}
	}
	return nil
}

func (vs VulnSrc) Get(release, pkgName string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, release)
	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get Fedora advisories: %w", err)
	}
	return advisories, nil
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
