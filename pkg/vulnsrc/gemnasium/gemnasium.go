package gemnasium

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
)

const (
	gemnasiumDir = "gemnasium"

	Conan PackageType = iota + 1
	Gem
	Go
	Maven
	Npm
	Nuget
	Packagist
	Pypi
)

var (
	supportIDPrefixes = []string{"CVE", "OSVDB", "GMS"}
	datasourceFormat  = "gemnasium-%s"
	PlatformSeperator = "::"
	platformFormat    = "Gemnasium Advisory %s"
)

type PackageType int

type VulnSrc struct {
	dbc         db.Operation
	packageType PackageType
}

func NewVulnSrc(packageType PackageType) VulnSrc {
	return VulnSrc{
		dbc:         db.Config{},
		packageType: packageType,
	}
}

func (vs VulnSrc) Update(dir string) error {
	var gemnasiums []GemnasiumAdvisory
	rootDir := filepath.Join(dir, "vuln-list", gemnasiumDir)

	err := utils.FileWalk(filepath.Join(rootDir, strings.ToLower(vs.packageType.String())), func(r io.Reader, path string) error {
		skip := true
		for _, IDPrefix := range supportIDPrefixes {
			_, fileName := filepath.Split(path)
			if strings.HasPrefix(fileName, IDPrefix) {
				skip = false
				break
			}
		}
		if skip {
			return nil
		}

		var gemnasium GemnasiumAdvisory
		if err := json.NewDecoder(r).Decode(&gemnasium); err != nil {
			return xerrors.Errorf("failed to decode Gemnasium: %w", err)
		}

		gemnasiums = append(gemnasiums, gemnasium)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in Gemnasium walk: %w", err)
	}

	if err = vs.save(gemnasiums); err != nil {
		return xerrors.Errorf("error in Gemnasium save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(gemnasiums []GemnasiumAdvisory) error {
	log.Println("Saveing Gemnasium DB")
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, gemnasiums)
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, gemnasiums []GemnasiumAdvisory) error {
	for _, gemnasium := range gemnasiums {
		a := types.Advisory{
			VulnerableVersions: []string{gemnasium.AffectedRange},
			PatchedVersions:    gemnasium.FixedVersions,
		}
		ss := strings.Split(gemnasium.PackageSlug, "/")
		if len(ss) < 2 {
			return xerrors.Errorf("failed to parse package slug: %s", gemnasium.PackageSlug)
		}
		pkgName := strings.Join(ss[1:], "/")

		err := vs.dbc.PutAdvisoryDetail(tx, gemnasium.Identifier, vs.packageType.platformName(), pkgName, a)
		if err != nil {
			return xerrors.Errorf("failed to save Gemnasium: %w", err)
		}

		vuln := types.VulnerabilityDetail{
			ID:           gemnasium.Identifier,
			Severity:     types.SeverityUnknown,
			References:   gemnasium.Urls,
			Title:        gemnasium.Title,
			Description:  gemnasium.Description,
			CvssVector:   gemnasium.CvssV2,
			CvssVectorV3: gemnasium.CvssV3,
		}
		if err = vs.dbc.PutVulnerabilityDetail(tx, gemnasium.Identifier, fmt.Sprintf(datasourceFormat, strings.ToLower(vs.packageType.String())), vuln); err != nil {
			return xerrors.Errorf("failed to save Gemnasium vulnerability detail: %w", err)
		}

		if err := vs.dbc.PutSeverity(tx, gemnasium.Identifier, types.SeverityUnknown); err != nil {
			return xerrors.Errorf("failed to save Gemnasium vulnerability severity: %w", err)
		}
	}

	return nil
}

func (pt PackageType) ConvertToEcosystem() string {
	switch pt {
	case Npm:
		return vulnerability.Npm
	case Packagist:
		return vulnerability.Composer
	case Pypi:
		return vulnerability.Pip
	case Gem:
		return vulnerability.RubyGems
	case Nuget:
		return vulnerability.NuGet
	case Maven:
		return vulnerability.Maven
	case Go:
		return vulnerability.Go
	case Conan:
		return vulnerability.Conan
	}
	return "Unknown"
}

func (e PackageType) String() string {
	switch e {
	case Conan:
		return "Conan"
	case Gem:
		return "Gem"
	case Go:
		return "Go"
	case Maven:
		return "Maven"
	case Npm:
		return "Npm"
	case Nuget:
		return "Nuget"
	case Packagist:
		return "Packagist"
	case Pypi:
		return "Pypi"
	}
	return "Unknown"
}

func (pt PackageType) platformName() string {
	return strings.Join(
		[]string{pt.ConvertToEcosystem(), fmt.Sprintf(platformFormat, pt)},
		PlatformSeperator,
	)
}
