package glad

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
	gladDir = "glad"

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
	supportedIDPrefixes = []string{"CVE", "OSVDB", "GMS"}
	datasourceFormat    = "glad-%s"
	PlatformSeperator   = "::"
	platformFormat      = "GitLab Advisory Database %s"
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
	var glads []GladAdvisory
	rootDir := filepath.Join(dir, "vuln-list", gladDir)

	err := utils.FileWalk(filepath.Join(rootDir, strings.ToLower(vs.packageType.String())), func(r io.Reader, path string) error {
		if !supportedIDs(filepath.Base(path)) {
			return nil
		}

		var glad GladAdvisory
		if err := json.NewDecoder(r).Decode(&glad); err != nil {
			return xerrors.Errorf("failed to decode GLAD: %w", err)
		}

		glads = append(glads, glad)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in GLAD walk: %w", err)
	}

	if err = vs.save(glads); err != nil {
		return xerrors.Errorf("error in GLAD save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(glads []GladAdvisory) error {
	log.Println("Saveing GLAD DB")
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, glads)
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, glads []GladAdvisory) error {
	for _, glad := range glads {
		a := types.Advisory{
			VulnerableVersions: []string{glad.AffectedRange},
			PatchedVersions:    glad.FixedVersions,
		}
		ss := strings.Split(glad.PackageSlug, "/")
		if len(ss) < 2 {
			return xerrors.Errorf("failed to parse package slug: %s", glad.PackageSlug)
		}

		pkgName := strings.Join(ss[1:], "/")
		if vs.packageType == Maven {
			pkgName = strings.Join(ss[1:], ":")
		}

		err := vs.dbc.PutAdvisoryDetail(tx, glad.Identifier, vs.packageType.platformName(), pkgName, a)
		if err != nil {
			return xerrors.Errorf("failed to save GLAD: %w", err)
		}

		vuln := types.VulnerabilityDetail{
			ID:           glad.Identifier,
			Severity:     types.SeverityUnknown,
			References:   glad.Urls,
			Title:        glad.Title,
			Description:  glad.Description,
			CvssVector:   glad.CvssV2,
			CvssVectorV3: glad.CvssV3,
		}
		if err = vs.dbc.PutVulnerabilityDetail(tx, glad.Identifier, fmt.Sprintf(datasourceFormat, strings.ToLower(vs.packageType.String())), vuln); err != nil {
			return xerrors.Errorf("failed to save GLAD vulnerability detail: %w", err)
		}

		if err := vs.dbc.PutSeverity(tx, glad.Identifier, types.SeverityUnknown); err != nil {
			return xerrors.Errorf("failed to save GLAD vulnerability severity: %w", err)
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

func supportedIDs(fileName string) bool {
	for _, prefix := range supportedIDPrefixes {
		if strings.HasPrefix(fileName, prefix) {
			return true
		}
	}
	return false
}
