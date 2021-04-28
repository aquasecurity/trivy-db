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

	Conan     PackageType = "Conan"
	Gem       PackageType = "Gem"
	Go        PackageType = "Go"
	Maven     PackageType = "Maven"
	Npm       PackageType = "Npm"
	Nuget     PackageType = "Nuget"
	Packagist PackageType = "Packagist"
	PyPI      PackageType = "PyPI"
)

var (
	supportedIDPrefixes = []string{"CVE", "OSVDB", "GMS"}
	datasourceFormat    = "glad-%s"
	PlatformSeperator   = "::"
	platformFormat      = "GitLab Advisory Database %s"
)

type PackageType string

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
	pkgType := strings.ToLower(string(vs.packageType))
	rootDir := filepath.Join(dir, "vuln-list", gladDir, pkgType)

	var glads []Advisory
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		if !supportedIDs(filepath.Base(path)) {
			return nil
		}

		var glad Advisory
		if err := json.NewDecoder(r).Decode(&glad); err != nil {
			return xerrors.Errorf("failed to decode GLAD: %w", err)
		}

		glads = append(glads, glad)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("walk error: %w", err)
	}

	if err = vs.save(glads); err != nil {
		return xerrors.Errorf("save error: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(glads []Advisory) error {
	log.Println("Saving GitLab Advisory Database")
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, glads)
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, glads []Advisory) error {
	for _, glad := range glads {
		a := types.Advisory{
			VulnerableVersions: []string{glad.AffectedRange},
			PatchedVersions:    glad.FixedVersions,
		}

		// e.g. "go/github.com/go-ldap/ldap" => "go", "github.com/go-ldap/ldap"
		ss := strings.SplitN(glad.PackageSlug, "/", 2)
		if len(ss) < 2 {
			return xerrors.Errorf("failed to parse package slug: %s", glad.PackageSlug)
		}

		pkgName := ss[1]
		if vs.packageType == Maven {
			// e.g. "maven/batik/batik-transcoder" => "maven", "batik:batik-transcoder"
			pkgName = strings.ReplaceAll(pkgName, "/", ":")
		}

		err := vs.dbc.PutAdvisoryDetail(tx, glad.Identifier, vs.packageType.platformName(), pkgName, a)
		if err != nil {
			return xerrors.Errorf("failed to save GLAD advisory detail: %w", err)
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

		source := fmt.Sprintf(datasourceFormat, strings.ToLower(string(vs.packageType)))
		if err = vs.dbc.PutVulnerabilityDetail(tx, glad.Identifier, source, vuln); err != nil {
			return xerrors.Errorf("failed to save GLAD vulnerability detail: %w", err)
		}

		if err = vs.dbc.PutSeverity(tx, glad.Identifier, types.SeverityUnknown); err != nil {
			return xerrors.Errorf("failed to save GLAD vulnerability severity: %w", err)
		}
	}

	return nil
}

func (pt PackageType) convertToEcosystem() string {
	switch pt {
	case Npm:
		return vulnerability.Npm
	case Packagist:
		return vulnerability.Composer
	case PyPI:
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

func (pt PackageType) platformName() string {
	return strings.Join(
		[]string{pt.convertToEcosystem(), fmt.Sprintf(platformFormat, pt)},
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
