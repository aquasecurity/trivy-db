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
	platformSUSELinuxFormat  = "SUSE Linux Enterprise %s"
	ErrNoSuchFileOrDirectory = " no such file or directory"
)

var (
	openSuseInstalledCommentRegexp = regexp.MustCompile(`openSUSE Leap ([\d+.]*)[A-Za-z\ ]* is installed`)
	suseInstalledCommentRegexp     = regexp.MustCompile(`SUSE Linux Enterprise[A-Za-z0-9\s]*? (\d+)\s?(SP(\d+)[-A-Za-z\s]*)?.* is installed`)
	slesInstalledCommentRegexp     = regexp.MustCompile(`sles10-sp(\d+)[A-Za-z-]* is installed`)
	sledInstalledCommentRegexp     = regexp.MustCompile(`sled10-sp(\d+)[A-Za-z-]* is installed`)
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
		if oval.Criteria.Operator == "" {
			continue
		}
		affectedPkgs := walkSUSE(oval.Criteria, "", Package{}, []AffectedPackage{})
		if len(affectedPkgs) == 0 {
			continue
		}
		count += len(affectedPkgs)

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

func getAffectedPackages(cri Criteria) []AffectedPackage {
	var osVers []string
	var pkgs []Package
	for _, c := range cri.Criterions {
		if strings.Contains(c.Comment, "is signed with openSUSE key") {
			continue
		}
		if strings.HasPrefix(c.Comment, "openSUSE ") {
			osVers = append(osVers, fmt.Sprintf(platformOpenSUSEFormat, openSuseInstalledCommentRegexp.FindStringSubmatch(c.Comment)[1]))
		}
		if strings.Contains(c.Comment, "SUSE Linux Enterprise ") {
			match := suseInstalledCommentRegexp.FindStringSubmatch(c.Comment)
			var osVer string
			if match[3] == "" {
				osVer = match[1]
			} else {
				osVer = fmt.Sprintf("%s.%s", match[1], match[3])
			}
			osVers = append(osVers, fmt.Sprintf(platformSUSELinuxFormat, osVer))
		}
		if strings.HasPrefix(c.Comment, "sles10-sp") {
			osVers = append(osVers, fmt.Sprintf(platformSUSELinuxFormat, "10."+slesInstalledCommentRegexp.FindStringSubmatch(c.Comment)[1]))
		}
		if strings.HasPrefix(c.Comment, "sled10-sp") {
			osVers = append(osVers, fmt.Sprintf(platformSUSELinuxFormat, "10."+sledInstalledCommentRegexp.FindStringSubmatch(c.Comment)[1]))
		}
		if strings.HasPrefix(c.Comment, "sles10-ltss") {
			osVers = append(osVers, fmt.Sprintf(platformSUSELinuxFormat, "10"))
		}
		if strings.HasPrefix(c.Comment, "sles10-slepos") {
			osVers = append(osVers, fmt.Sprintf(platformSUSELinuxFormat, "10"))
		}

		packVer := ""
		if strings.HasSuffix(c.Comment, " is installed") {
			packVer = strings.TrimSuffix(c.Comment, " is installed")
		} else if strings.Contains(c.Comment, " less than ") {
			packVer = strings.Join(strings.Split(c.Comment, " less than "), "-")
		}
		if packVer != "" {
			ss := strings.Split(packVer, "-")
			if len(ss) < 2 {
				continue
			}
			name := strings.Join(ss[0:len(ss)-2], "-")
			version := fmt.Sprintf("%s-%s", ss[len(ss)-2], ss[len(ss)-1])
			pkgs = append(pkgs, Package{
				Name:         name,
				FixedVersion: version,
			})
		} else {
			log.Printf("%s can't parse", c.Comment)
		}
	}
	for _, ca := range cri.Criterias {
		for _, c := range ca.Criterions {
			if strings.Contains(c.Comment, "is signed with openSUSE key") {
				continue
			}
			if strings.HasPrefix(c.Comment, "openSUSE ") {
				osVers = append(osVers, fmt.Sprintf(platformOpenSUSEFormat, openSuseInstalledCommentRegexp.FindStringSubmatch(c.Comment)[1]))
			}
			if strings.Contains(c.Comment, "SUSE Linux Enterprise ") {
				match := suseInstalledCommentRegexp.FindStringSubmatch(c.Comment)
				var osVer string
				if match[3] == "" {
					osVer = match[1]
				} else {
					osVer = fmt.Sprintf("%s.%s", match[1], match[3])
				}
				osVers = append(osVers, fmt.Sprintf(platformSUSELinuxFormat, osVer))
			}
			if strings.HasPrefix(c.Comment, "sles10-sp") {
				osVers = append(osVers, fmt.Sprintf(platformSUSELinuxFormat, "10."+slesInstalledCommentRegexp.FindStringSubmatch(c.Comment)[1]))
			}
			if strings.HasPrefix(c.Comment, "sled10-sp") {
				osVers = append(osVers, fmt.Sprintf(platformSUSELinuxFormat, "10."+sledInstalledCommentRegexp.FindStringSubmatch(c.Comment)[1]))
			}
			if strings.HasPrefix(c.Comment, "sles10-ltss") {
				osVers = append(osVers, fmt.Sprintf(platformSUSELinuxFormat, "10"))
			}
			if strings.HasPrefix(c.Comment, "sles10-slepos") {
				osVers = append(osVers, fmt.Sprintf(platformSUSELinuxFormat, "10"))
			}

			packVer := ""
			if strings.HasSuffix(c.Comment, " is installed") {
				packVer = strings.TrimSuffix(c.Comment, " is installed")
			} else if strings.Contains(c.Comment, " less than ") {
				packVer = strings.Join(strings.Split(c.Comment, " less than "), "-")
			}
			if packVer != "" {
				ss := strings.Split(packVer, "-")
				if len(ss) < 2 {
					continue
				}
				name := strings.Join(ss[0:len(ss)-2], "-")
				version := fmt.Sprintf("%s-%s", ss[len(ss)-2], ss[len(ss)-1])
				pkgs = append(pkgs, Package{
					Name:         name,
					FixedVersion: version,
				})
			} else {
				log.Printf("%s can't parse", c.Comment)
			}

		}
	}

	var affectedPackages []AffectedPackage
	for _, osVer := range osVers {
		for _, pkg := range pkgs {
			affectedPackages = append(affectedPackages, AffectedPackage{
				OSVer:   osVer,
				Package: pkg,
			})
		}
	}

	return affectedPackages
}

func walkSUSE(cri Criteria, osVer string, pkg Package, pkgs []AffectedPackage) []AffectedPackage {
	var affectedPackages []AffectedPackage
	if cri.Operator == "OR" {
		for _, c := range cri.Criterias {
			if len(cri.Criterions) == 0 {
				affectedPackages = append(affectedPackages, getAffectedPackages(c)...)
			}
			affectedPackages = recursiveGetAffectedPackages(c, "", Package{}, affectedPackages)
		}
	} else if cri.Operator == "AND" {
		if len(cri.Criterions) == 0 {
			affectedPackages = append(affectedPackages, getAffectedPackages(cri)...)
		}
		affectedPackages = recursiveGetAffectedPackages(cri, "", Package{}, affectedPackages)
	}
	return affectedPackages
}

func recursiveGetAffectedPackages(cri Criteria, osVer string, pkg Package, pkgs []AffectedPackage) []AffectedPackage {
	for _, c := range cri.Criterions {
		osIsFind := false
		if strings.Contains(c.Comment, "is signed with openSUSE key") {
			continue
		}
		if strings.HasPrefix(c.Comment, "openSUSE ") {
			osVer = fmt.Sprintf(platformOpenSUSEFormat, openSuseInstalledCommentRegexp.FindStringSubmatch(c.Comment)[1])
			osIsFind = true
		}
		if strings.Contains(c.Comment, "SUSE Linux Enterprise ") {
			match := suseInstalledCommentRegexp.FindStringSubmatch(c.Comment)
			if match[3] == "" {
				osVer = match[1]
			} else {
				osVer = fmt.Sprintf("%s.%s", match[1], match[3])
			}
			osVer = fmt.Sprintf(platformSUSELinuxFormat, osVer)
			osIsFind = true
		}
		if strings.HasPrefix(c.Comment, "sles10-sp") {
			osVer = fmt.Sprintf(platformSUSELinuxFormat, "10."+slesInstalledCommentRegexp.FindStringSubmatch(c.Comment)[1])
			osIsFind = true
		}

		if strings.HasPrefix(c.Comment, "sled10-sp") {
			osVer = fmt.Sprintf(platformSUSELinuxFormat, "10."+sledInstalledCommentRegexp.FindStringSubmatch(c.Comment)[1])
			osIsFind = true
		}
		if strings.HasPrefix(c.Comment, "sles10-ltss") {
			osVer = fmt.Sprintf(platformSUSELinuxFormat, "10")
			osIsFind = true
		}
		if strings.HasPrefix(c.Comment, "sles10-slepos") {
			osVer = fmt.Sprintf(platformSUSELinuxFormat, "10")
			osIsFind = true
		}

		packVer := ""
		if strings.HasSuffix(c.Comment, " is installed") {
			packVer = strings.TrimSuffix(c.Comment, " is installed")
		} else if strings.Contains(c.Comment, " less than ") {
			packVer = strings.Join(strings.Split(c.Comment, " less than "), "-")
		}
		if !osIsFind {
			ss := strings.Split(packVer, "-")
			if len(ss) < 2 {
				continue
			}
			name := strings.Join(ss[0:len(ss)-2], "-")
			version := fmt.Sprintf("%s-%s", ss[len(ss)-2], ss[len(ss)-1])
			pkg = Package{
				Name:         name,
				FixedVersion: version,
			}
		}

		if (osVer == "") || (pkg == Package{}) {
			continue
		}

		pkgs = append(pkgs, AffectedPackage{
			OSVer:   osVer,
			Package: pkg,
		})
	}

	for _, c := range cri.Criterias {
		pkgs = recursiveGetAffectedPackages(c, osVer, pkg, pkgs)
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
