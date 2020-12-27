package redhat2

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/types"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/utils"
)

const (
	platformFormat = "Red Hat Enterprise Linux %s"
)

var (
	redhatDir       = filepath.Join("oval", "redhat2")
	targetPlatforms = []string{"Red Hat Enterprise Linux 5", "Red Hat Enterprise Linux 6", "Red Hat Enterprise Linux 7", "Red Hat Enterprise Linux 8"}

	platformDirFormat = "%s-including-unpatched"
	supportPlatform   = []string{"rhel-5", "rhel-6", "rhel-7", "rhel-8"}
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
	rootDir := filepath.Join(dir, "vuln-list", redhatDir)

	var advisories []RedhatOVAL
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		// path:  ~/Caches/trivy-db/vuln-list/oval/redhat2/8/storage-gluster-3-including-unpatched/definitions/2020/CVE-2020-1472.json
		// TODO: Skip unsupportPlatform

		var advisory RedhatOVAL
		if err := json.NewDecoder(r).Decode(&advisory); err != nil {
			return xerrors.Errorf("failed to decode Red Hat OVAL JSON: %w", err)
		}
		advisories = append(advisories, advisory)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in Red Hat OVAL walk: %w", err)
	}

	if err = vs.save(advisories); err != nil {
		return xerrors.Errorf("error in Red Hat OVAL save: %w", err)
	}

	return nil
}

func (vs VulnSrc) walkRedhat(cri Criteria, pkgs []Package) []Package {
	for _, c := range cri.Criterions {
		// e.g. firefox is earlier than 0:60.6.1-1.el8
		ss := strings.Split(c.Comment, " is earlier than ")
		if len(ss) != 2 {
			continue
		}

		pkgs = append(pkgs, Package{
			Name:         ss[0],
			FixedVersion: strings.TrimSpace(ss[1]),
		})
	}

	if len(cri.Criterias) == 0 {
		return pkgs
	}
	for _, c := range cri.Criterias {
		pkgs = vs.walkRedhat(c, pkgs)
	}
	return pkgs
}
func (vs VulnSrc) commit(tx *bolt.Tx, advisories []RedhatOVAL) error {
	// for _, advisory := range advisories {
	// 	platforms := vs.getPlatforms(advisory.Affecteds)
	// 	if len(platforms) != 1 {
	// 		log.Printf("Invalid advisory: %s\n", advisory.ID)
	// 		continue
	// 	}
	// 	platformName := fmt.Sprintf(platformFormat, platforms[0])
	// 	affectedPkgs := vs.walkRedhat(advisory.Criteria, []Package{})
	// 	for _, affectedPkg := range affectedPkgs {
	// 		for _, cve := range advisory.Advisory.Cves {
	// 			advisory := types.Advisory{
	// 				FixedVersion: affectedPkg.FixedVersion,
	// 			}
	// 			if err := vs.dbc.PutAdvisoryDetail(tx, cve.CveID, platformName, affectedPkg.Name, advisory); err != nil {
	// 				return xerrors.Errorf("failed to save Red Hat OVAL advisory: %w", err)
	// 			}
	// 		}
	// 	}
	// }
	return nil
}

func (vs VulnSrc) save(ovals []RedhatOVAL) error {
	log.Println("Saving RedHat DB")
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, ovals)
	})
	if err != nil {
		return xerrors.Errorf("failed batch update: %w", err)
	}
	return nil
}

func (vs VulnSrc) Get(majorVersion string, pkgName string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, majorVersion)
	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get Red Hat advisories: %w", err)
	}
	return advisories, nil
}

func severityFromThreat(sev string) types.Severity {
	switch strings.Title(sev) {
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

func (vs VulnSrc) getPlatforms(affectedList []Affected) []string {
	var platforms []string
	// for _, affected := range affectedList {
	// 	for _, platform := range affected.Platforms {
	// 		match := platformRegexp.FindStringSubmatch(platform)
	// 		if len(match) < 2 {
	// 			continue
	// 		}
	// 		majorVersion := match[1]
	// 		if !utils.StringInSlice(majorVersion, supportedPlatform) {
	// 			continue
	// 		}
	// 		platforms = append(platforms, majorVersion)
	// 	}
	// }
	return platforms
}
