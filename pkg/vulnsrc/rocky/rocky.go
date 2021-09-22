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
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	rockyDir = "rocky"
)

var (
	platformFormat = "rocky %s"
	targetReleases = []string{"8"}
	targetRepos    = []string{"BaseOS", "AppStream", "Devel"}
	targetArches   = []string{"x86_64"}
)

type VulnSrc struct {
	dbc db.Operation
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Name() string {
	return vulnerability.Rocky
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", rockyDir)
	errata := map[string][]RLSA{}
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var erratum RLSA
		if err := json.NewDecoder(r).Decode(&erratum); err != nil {
			return xerrors.Errorf("failed to decode Rocky erratum: %w", err)
		}

		dirs := strings.Split(path, string(filepath.Separator))
		if len(dirs) < 5 {
			log.Printf("invalid path: %s\n", path)
			return nil
		}

		majorVer := dirs[len(dirs)-5]
		if !utils.StringInSlice(majorVer, targetReleases) {
			log.Printf("unsupported Rocky version: %s\n", majorVer)
			return nil
		}
		repo := dirs[len(dirs)-4]
		if !utils.StringInSlice(repo, targetRepos) {
			log.Printf("unsupported Rocky repo: %s\n", repo)
			return nil
		}
		arch := dirs[len(dirs)-3]
		if !utils.StringInSlice(arch, targetArches) {
			switch arch {
			case "aarch64":
			default:
				log.Printf("unsupported Rocky arch: %s\n", arch)
			}
			return nil
		}

		errata[majorVer] = append(errata[majorVer], erratum)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in Rocky walk: %w", err)
	}

	if err := vs.save(errata); err != nil {
		return xerrors.Errorf("error in Rocky save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(errataVer map[string][]RLSA) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		for majorVer, errata := range errataVer {
			platformName := fmt.Sprintf(platformFormat, majorVer)
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

func (vs VulnSrc) commit(tx *bolt.Tx, platformName string, errata []RLSA) error {
	for _, erratum := range errata {
		for _, cveID := range erratum.CveIDs {
			for _, pkg := range erratum.Packages {
				advisory := types.Advisory{
					FixedVersion: constructVersion(pkg.Epoch, pkg.Version, pkg.Release),
				}
				if err := vs.dbc.PutAdvisoryDetail(tx, cveID, platformName, pkg.Name, advisory); err != nil {
					return xerrors.Errorf("failed to save Rocky advisory: %w", err)
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
				if err := vs.dbc.PutVulnerabilityDetail(tx, cveID, vulnerability.Rocky, vuln); err != nil {
					return xerrors.Errorf("failed to save Rocky vulnerability: %w", err)
				}

				if err := vs.dbc.PutVulnerabilityID(tx, cveID); err != nil {
					return xerrors.Errorf("failed to save the vulnerability ID: %w", err)
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
		return nil, xerrors.Errorf("failed to get Rocky advisories: %w", err)
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
