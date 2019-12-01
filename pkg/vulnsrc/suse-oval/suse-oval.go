package suseoval

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"

	bolt "github.com/etcd-io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"golang.org/x/xerrors"
)

const (
	platformOpenSUSEFormat   = "OpenSUSE Leap %s"
	platformSUSELinuxFormat  = "SUSE Enterprise Linux %s"
	ErrNoSuchFileOrDirectory = " no such file or directory"
)

var (
	platformFormat = ""
	suseDirs       = []string{
		filepath.Join("oval", "suse", "opensuse.leap", "15.0"),
		filepath.Join("oval", "suse", "opensuse.leap", "15.1"),
		filepath.Join("oval", "suse", "opensuse.leap", "42.3"),
		filepath.Join("oval", "suse", "suse.linux.enterprise", "12"),
		filepath.Join("oval", "suse", "suse.linux.enterprise", "15"),
		filepath.Join("oval", "suse", "suse.linux.enterprise.desktop", "10"),
		filepath.Join("oval", "suse", "suse.linux.enterprise.desktop", "11"),
		filepath.Join("oval", "suse", "suse.linux.enterprise.desktop", "12"),
		filepath.Join("oval", "suse", "suse.linux.enterprise.desktop", "15"),
		filepath.Join("oval", "suse", "suse.linux.enterprise.server", "10"),
		filepath.Join("oval", "suse", "suse.linux.enterprise.server", "11"),
		filepath.Join("oval", "suse", "suse.linux.enterprise.server", "12"),
		filepath.Join("oval", "suse", "suse.linux.enterprise.server", "15"),
	}
)

type VulnSrc struct {
	dbc db.Operations
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Update(dir string) error {
	log.Println("Saving SUSE OVAL")

	for _, suseDir := range suseDirs {
		rootDir := filepath.Join(dir, "vuln-list", suseDir)
		platformFormat = platformSUSELinuxFormat
		if strings.Contains(suseDir, "opensuse.leap") {
			platformFormat = platformOpenSUSEFormat
		}

		var ovals []SuseOVAL
		err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
			var oval SuseOVAL
			if err := json.NewDecoder(r).Decode(&oval); err != nil {
				return xerrors.Errorf("failed to decode SUSE OVAL JSON: %w %+v", err, oval)
			}
			ovals = append(ovals, oval)
			return nil
		})
		if err != nil {
			if strings.HasSuffix(err.Error(), ErrNoSuchFileOrDirectory) {
				log.Printf("%s is not exist", rootDir)
				continue
			}
			return xerrors.Errorf("error in SUSE OVAL walk: %w", err)
		}

		platformName := fmt.Sprintf(platformFormat, suseDir[strings.LastIndex(suseDir, "/")+1:])
		if err = vs.save(ovals, platformName); err != nil {
			return xerrors.Errorf("error in SUSE OVAL save: %w", err)
		}

	}
	return nil

}

func (vs VulnSrc) save(ovals []SuseOVAL, platformName string) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, ovals, platformName)
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}

	return nil

}

func (vs VulnSrc) commit(tx *bolt.Tx, ovals []SuseOVAL, platformName string) error {
	osVer := platformName[strings.LastIndex(platformName, " "):]
	for _, oval := range ovals {
		affectedPkgs := walkSUSE(oval.Criteria, osVer, []AffectedPackage{})
		if len(affectedPkgs) == 0 {
			continue
		}

		for _, affectedPkg := range affectedPkgs {
			if affectedPkg.Package.Name == "" {
				continue
			}

			advisory := types.Advisory{
				FixedVersion: affectedPkg.Package.FixedVersion,
			}

			if err := vs.dbc.PutAdvisory(tx, platformName, affectedPkg.Package.Name, oval.Title, advisory); err != nil {
				return xerrors.Errorf("failed to save %s OVAL: %w", platformName, err)
			}
		}

		var references []string
		for _, ref := range oval.References {
			references = append(references, ref.URI)
		}

		vuln := types.VulnerabilityDetail{
			Description: strings.TrimSpace(oval.Description),
			References:  references,
			Title:       oval.Title,
			Severity:    severityFromThreat(oval.Severity),
		}
		if err := vs.dbc.PutVulnerabilityDetail(tx, oval.Title, vulnerability.SuseOVAL, vuln); err != nil {
			return xerrors.Errorf("failed to save %s OVAL vulnerability: %w", platformName, err)
		}

		// for light DB
		if err := vs.dbc.PutSeverity(tx, oval.Title, types.SeverityUnknown); err != nil {
			return xerrors.Errorf("failed to save %s vulnerability severity: %w", platformName, err)
		}
	}
	return nil
}

func walkSUSE(cri Criteria, osVer string, pkgs []AffectedPackage) []AffectedPackage {
	for _, c := range cri.Criterions {
		if strings.HasPrefix(c.Comment, "openSUSE ") {
			continue
		}
		if strings.HasPrefix(c.Comment, "SUSE Linux Enterprise ") {
			continue
		}
		if strings.HasPrefix(c.Comment, "sles10-sp") {
			continue
		}
		if strings.HasPrefix(c.Comment, "SUSE") {
			return pkgs
		}
		if strings.Contains(c.Comment, "is signed with openSUSE key") {
			continue
		}

		packVer := ""
		if strings.HasSuffix(c.Comment, " is installed") {
			packVer = strings.TrimSuffix(c.Comment, " is installed")
		} else if strings.Contains(c.Comment, " less than ") {
			packVer = strings.Join(strings.Split(c.Comment, " less than "), "-")
		}

		if packVer == "" {
			fmt.Printf("%s can't parse", c.Comment)
		}

		ss := strings.Split(packVer, "-")
		if len(ss) < 2 {
			continue
		}
		name := strings.Join(ss[0:len(ss)-2], "-")
		version := fmt.Sprintf("%s-%s", ss[len(ss)-2], ss[len(ss)-1])

		pkgs = append(pkgs, AffectedPackage{
			OSVer: osVer,
			Package: Package{
				Name:         name,
				FixedVersion: version,
			},
		})
	}

	for _, c := range cri.Criterias {
		pkgs = walkSUSE(c, osVer, pkgs)
	}
	return pkgs
}

func (vs VulnSrc) Get(release string, pkgName string) ([]types.Advisory, error) {
	advisories, err := vs.dbc.GetAdvisories(release, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get SUSE advisories: %w", err)
	}
	return advisories, nil
}

func severityFromThreat(sev string) types.Severity {
	switch sev {
	case "Low":
		return types.SeverityLow
	case "Moderate":
		return types.SeverityMedium
	case "Important":
		return types.SeverityHigh
	case "Critical":
		return types.SeverityCritical
	}
	return types.SeverityUnknown
}
