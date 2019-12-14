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
	openSuseInstalledCommentRegexp  = regexp.MustCompile(`openSUSE Leap ([\d+.]*)[A-Za-z\ ]* is installed`)
	suseInstalledCommentRegexp      = regexp.MustCompile(`SUSE Linux Enterprise[A-Za-z0-9\s]*? (\d+)\s?(SP(\d+)[-A-Za-z\s]*)?.* is installed`)
	summrizedInstalledCommentRegexp = regexp.MustCompile(`(sles|sled)(\d+)-(sp(\d+))*[A-Za-z]* is installed`)
	suseDir                         = filepath.Join("oval", "suse")
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

func walkSUSE(cri Criteria, osVer string, pkg Package, pkgs []AffectedPackage) []AffectedPackage {
	var affectedPackages []AffectedPackage
	if cri.Operator == "OR" {
		for _, c := range cri.Criterias {
			if len(cri.Criterions) == 0 {
				affectedPackages = append(affectedPackages, getAffectedPackages(c)...)
			}
			affectedPackages = recursiveGetAffectedPackages(c, "", Package{}, affectedPackages)
		}
	}
	if cri.Operator == "AND" {
		if len(cri.Criterions) == 0 {
			affectedPackages = append(affectedPackages, getAffectedPackages(cri)...)
		}
		affectedPackages = recursiveGetAffectedPackages(cri, "", Package{}, affectedPackages)
	}

	return affectedPackages
}

func recursiveGetAffectedPackages(cri Criteria, osVer string, pkg Package, pkgs []AffectedPackage) []AffectedPackage {
	for _, c := range cri.Criterions {
		if strings.Contains(c.Comment, "is signed with openSUSE key") {
			continue
		}
		osVerResult := getOSVersion(c.Comment)
		if osVerResult != "" {
			osVer = osVerResult
		}

		if osVerResult == "" {
			pkg = getPackage(c.Comment)
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

func getAffectedPackages(cri Criteria) []AffectedPackage {
	var osVers []string
	var pkgs []Package

	criterions := cri.Criterions
	for _, c := range cri.Criterias {
		for _, criterion := range c.Criterions {
			criterions = append(criterions, criterion)
		}
	}

	for _, c := range criterions {
		if strings.Contains(c.Comment, "is signed with openSUSE key") {
			continue
		}

		if osVerResult := getOSVersion(c.Comment); osVerResult != "" {
			osVers = append(osVers, osVerResult)
		}

		if pkg := getPackage(c.Comment); pkg != (Package{}) {
			pkgs = append(pkgs, pkg)
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

func getOSVersion(comment string) string {
	if strings.HasPrefix(comment, "openSUSE ") {
		return fmt.Sprintf(platformOpenSUSEFormat, openSuseInstalledCommentRegexp.FindStringSubmatch(comment)[1])
	}
	if match := suseInstalledCommentRegexp.FindStringSubmatch(comment); len(match) != 0 {
		var osVer string
		if match[3] == "" {
			osVer = match[1]
		} else {
			osVer = fmt.Sprintf("%s.%s", match[1], match[3])
		}
		return fmt.Sprintf(platformSUSELinuxFormat, osVer)
	}
	if match := summrizedInstalledCommentRegexp.FindStringSubmatch(comment); len(match) != 0 {
		var osVer string
		if match[4] == "" {
			osVer = match[2]
		} else {
			osVer = fmt.Sprintf("%s.%s", match[2], match[4])
		}
		return fmt.Sprintf(platformSUSELinuxFormat, osVer)
	}
	return ""
}

func getPackage(comment string) Package {
	packVer := ""
	if strings.HasSuffix(comment, " is installed") {
		packVer = strings.TrimSuffix(comment, " is installed")
	} else if strings.Contains(comment, " less than ") {
		packVer = strings.Join(strings.Split(comment, " less than "), "-")
	}

	ss := strings.Split(packVer, "-")
	if len(ss) < 2 {
		return Package{}
	}
	name := strings.Join(ss[0:len(ss)-2], "-")
	version := fmt.Sprintf("%s-%s", ss[len(ss)-2], ss[len(ss)-1])

	return Package{
		Name:         name,
		FixedVersion: version,
	}
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
