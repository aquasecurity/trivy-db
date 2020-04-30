package redhatoval

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/types"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/utils"
)

var (
	redhatDir = filepath.Join("oval", "redhat")

	// the same bucket name as Red Hat Security Data API
	platformFormat = "Red Hat Enterprise Linux %s"

	supportedPlatform = []string{"5", "6", "7", "8"}
	platformRegexp    = regexp.MustCompile(`Red Hat Enterprise Linux (\d)`)
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

// fromhttps://github.com/kotakanbe/goval-dictionary/blob/eff7f862637c3536b5ffef5a255bd1dd2779f582/models/redhat.go
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

func (vs VulnSrc) save(advisories []RedhatOVAL) error {
	log.Println("Saving Red Hat OVAL")
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, advisories)
	})
	if err != nil {
		return xerrors.Errorf("failed batch update: %w", err)
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, advisories []RedhatOVAL) error {
	for _, advisory := range advisories {
		platforms := vs.getPlatforms(advisory.Affecteds)
		if len(platforms) != 1 {
			log.Printf("Invalid advisory: %s\n", advisory.ID)
			continue
		}
		platformName := fmt.Sprintf(platformFormat, platforms[0])
		affectedPkgs := vs.walkRedhat(advisory.Criteria, []Package{})
		for _, affectedPkg := range affectedPkgs {
			for _, cve := range advisory.Advisory.Cves {
				advisory := types.Advisory{
					FixedVersion: affectedPkg.FixedVersion,
				}
				if err := vs.dbc.PutAdvisory(tx, platformName, affectedPkg.Name, cve.CveID, advisory); err != nil {
					return xerrors.Errorf("failed to save Red Hat OVAL advisory: %w", err)
				}
			}
		}
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

func (vs VulnSrc) getPlatforms(affectedList []Affected) []string {
	var platforms []string
	for _, affected := range affectedList {
		for _, platform := range affected.Platforms {
			match := platformRegexp.FindStringSubmatch(platform)
			if len(match) < 2 {
				continue
			}
			majorVersion := match[1]
			if !utils.StringInSlice(majorVersion, supportedPlatform) {
				continue
			}
			platforms = append(platforms, majorVersion)
		}
	}
	return platforms
}
