package suseoval

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"regexp"
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
	openSuseInstalledCommentRegexp = regexp.MustCompile(`openSUSE Leap ([\d+.]*)[A-Za-z\ ]* is installed`)
	suseInstalledCommentRegexp     = regexp.MustCompile(`SUSE Linux Enterprise[A-Za-z0-9\s]*? (\d+)\s?(SP(\d+)[-A-Za-z\s]*)?.* is installed`)
	slesInstalledCommentRegexp     = regexp.MustCompile(`sles10-sp(\d+)[A-Za-z-]* is installed`)
	suseDir                        = filepath.Join("oval", "suse")
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

	rootDir := filepath.Join(dir, "vuln-list", suseDir)
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
		return xerrors.Errorf("error in SUSE OVAL walk: %w", err)
	}

	if err = vs.save(ovals); err != nil {
		return xerrors.Errorf("error in SUSE OVAL save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(ovals []SuseOVAL) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, ovals)
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, ovals []SuseOVAL) error {
	for _, oval := range ovals {
		affectedPkgs := walkSUSE(oval.Criteria, "", []AffectedPackage{})
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

			if err := vs.dbc.PutAdvisory(tx, affectedPkg.OSVer, affectedPkg.Package.Name, oval.Title, advisory); err != nil {
				return xerrors.Errorf("failed to save %q OVAL: %w", affectedPkg.OSVer, err)
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
			return xerrors.Errorf("failed to save SUSE OVAL vulnerability: %w", err)
		}

		// for light DB
		if err := vs.dbc.PutSeverity(tx, oval.Title, types.SeverityUnknown); err != nil {
			return xerrors.Errorf("failed to save SUSE vulnerability severity: %w", err)
		}
	}
	return nil
}

func walkSUSE(cri Criteria, osVer string, pkgs []AffectedPackage) []AffectedPackage {
	for _, c := range cri.Criterions {
		if strings.Contains(c.Comment, "is signed with openSUSE key") {
			continue
		}
		if strings.HasPrefix(c.Comment, "openSUSE ") {
			osVer = fmt.Sprintf(platformOpenSUSEFormat, openSuseInstalledCommentRegexp.FindStringSubmatch(c.Comment)[1])
		}
		if strings.HasPrefix(c.Comment, "SUSE Linux Enterprise ") {
			match := suseInstalledCommentRegexp.FindStringSubmatch(c.Comment)
			if match[3] == "" {
				osVer = match[1]
			} else {
				osVer = fmt.Sprintf("%s.%s", match[1], match[3])
			}
			osVer = fmt.Sprintf(platformSUSELinuxFormat, osVer)
		}
		if strings.HasPrefix(c.Comment, "sles10-sp") {
			osVer = fmt.Sprintf(platformSUSELinuxFormat, "10."+slesInstalledCommentRegexp.FindStringSubmatch(c.Comment)[1])
		}
		if osVer == "" {
			continue
		}

		packVer := ""
		if strings.HasSuffix(c.Comment, " is installed") {
			packVer = strings.TrimSuffix(c.Comment, " is installed")
		} else if strings.Contains(c.Comment, " less than ") {
			packVer = strings.Join(strings.Split(c.Comment, " less than "), "-")
		}

		if packVer == "" {
			log.Printf("%s can't parse", c.Comment)
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
