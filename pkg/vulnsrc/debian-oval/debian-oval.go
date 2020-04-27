package debianoval

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/types"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/debian"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

var (
	debianDir = filepath.Join("oval", "debian")
	// e.g. debian oval 8
	platformFormat = "debian oval %s"
)

type VulnSrc struct {
	dbc db.Operation
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", debianDir)

	var cves []DebianOVAL
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var cve DebianOVAL
		if err := json.NewDecoder(r).Decode(&cve); err != nil {
			return xerrors.Errorf("failed to decode Debian OVAL JSON: %w", err)
		}

		dirs := strings.Split(path, string(os.PathSeparator))
		if len(dirs) < 3 {
			log.Printf("invalid path: %s\n", path)
			return nil
		}
		cve.Release = dirs[len(dirs)-3]
		cves = append(cves, cve)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in Debian OVAL walk: %w", err)
	}

	if err = vs.save(cves); err != nil {
		return xerrors.Errorf("error in Debian OVAL save: %w", err)
	}

	return nil
}

// from https://github.com/kotakanbe/goval-dictionary/blob/c462c07a5cd0b6de52f167e9aa4298083edfc356/models/debian.go#L53
func walkDebian(cri Criteria, pkgs []Package) []Package {
	for _, c := range cri.Criterions {
		ss := strings.Split(c.Comment, " DPKG is earlier than ")
		if len(ss) != 2 {
			continue
		}

		// "0" means notyetfixed or erroneous information.
		// Not available because "0" includes erroneous info...
		if ss[1] == "0" {
			continue
		}
		pkgs = append(pkgs, Package{
			Name:         ss[0],
			FixedVersion: strings.Split(ss[1], " ")[0],
		})
	}

	if len(cri.Criterias) == 0 {
		return pkgs
	}
	for _, c := range cri.Criterias {
		pkgs = walkDebian(c, pkgs)
	}
	return pkgs
}

func (vs VulnSrc) save(cves []DebianOVAL) error {
	log.Println("Saving Debian OVAL")
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		for _, cve := range cves {
			affectedPkgs := walkDebian(cve.Criteria, []Package{})
			for _, affectedPkg := range affectedPkgs {
				// stretch => 9
				majorVersion, ok := debian.DebianReleasesMapping[cve.Release]
				if !ok {
					continue
				}
				platformName := fmt.Sprintf(platformFormat, majorVersion)
				cveID := cve.Metadata.Title
				advisory := types.Advisory{
					FixedVersion: affectedPkg.FixedVersion,
				}
				if err := vs.dbc.PutAdvisory(tx, platformName, affectedPkg.Name, cveID, advisory); err != nil {
					return xerrors.Errorf("failed to save Debian OVAL advisory: %w", err)
				}

				var references []string
				for _, ref := range cve.Metadata.References {
					references = append(references, ref.RefURL)
				}

				vuln := types.VulnerabilityDetail{
					Description: cve.Metadata.Description,
					References:  references,
				}

				if err := vs.dbc.PutVulnerabilityDetail(tx, cveID, vulnerability.DebianOVAL, vuln); err != nil {
					return xerrors.Errorf("failed to save Debian OVAL vulnerability: %w", err)
				}

				// for light DB
				if err := vs.dbc.PutSeverity(tx, cveID, types.SeverityUnknown); err != nil {
					return xerrors.Errorf("failed to save alpine vulnerability severity: %w", err)
				}
			}
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}

	return nil
}

func (vs VulnSrc) Get(release string, pkgName string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, release)
	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get Alpine advisories: %w", err)
	}
	return advisories, nil
}
