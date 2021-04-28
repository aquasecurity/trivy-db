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

	Conan     packageType = "Conan"
	Gem       packageType = "Gem"
	Go        packageType = "Go"
	Maven     packageType = "Maven"
	Npm       packageType = "Npm"
	Nuget     packageType = "Nuget"
	Packagist packageType = "Packagist"
	PyPI      packageType = "PyPI"
)

var (
	// TODO: support Conan and Packagist
	supportedPkgTypes   = []packageType{Gem, Go, Maven, Npm, Nuget, PyPI}
	supportedIDPrefixes = []string{"CVE", "OSVDB", "GMS"}
	PlatformSeperator   = "::"
	platformFormat      = "GitLab Advisory Database %s"
)

type packageType string

type VulnSrc struct {
	dbc db.Operation
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Update(dir string) error {
	for _, t := range supportedPkgTypes {
		log.Printf("Update GitLab Advisory Database %s", t)
		rootDir := filepath.Join(dir, "vuln-list", gladDir, strings.ToLower(string(t)))
		if err := vs.update(t, rootDir); err != nil {
			return xerrors.Errorf("update error: %w", err)
		}
	}
	return nil
}

func (vs VulnSrc) update(pkgType packageType, rootDir string) error {
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

	if err = vs.save(pkgType, glads); err != nil {
		return xerrors.Errorf("save error: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(pkgType packageType, glads []Advisory) error {
	log.Printf("Saving GitLab Advisory Database %s...", pkgType)
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, pkgType, glads)
	})
	if err != nil {
		return xerrors.Errorf("batch update error: %w", err)
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, pkgType packageType, glads []Advisory) error {
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
		if pkgType == Maven {
			// e.g. "maven/batik/batik-transcoder" => "maven", "batik:batik-transcoder"
			pkgName = strings.ReplaceAll(pkgName, "/", ":")
		}

		err := vs.dbc.PutAdvisoryDetail(tx, glad.Identifier, pkgType.platformName(), pkgName, a)
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

		if err = vs.dbc.PutVulnerabilityDetail(tx, glad.Identifier, vulnerability.GLAD, vuln); err != nil {
			return xerrors.Errorf("failed to save GLAD vulnerability detail: %w", err)
		}

		if err = vs.dbc.PutSeverity(tx, glad.Identifier, types.SeverityUnknown); err != nil {
			return xerrors.Errorf("failed to save GLAD vulnerability severity: %w", err)
		}
	}

	return nil
}

func (pt packageType) convertToEcosystem() string {
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

func (pt packageType) platformName() string {
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
