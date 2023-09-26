package glad

import (
	"encoding/json"
	"io"
	"log"
	"path/filepath"
	"strings"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	// GitLab Advisory Database
	gladDir = "glad"

	Conan packageType = "Conan"
	Maven packageType = "Maven"
)

var (
	supportedIDPrefixes = []string{
		"CVE",
		"GHSA",
		"GMS",
	}

	ecosystems = map[packageType]types.Ecosystem{
		Maven: vulnerability.Maven,
		Conan: vulnerability.Conan,
	}

	source = types.DataSource{
		ID:   vulnerability.GLAD,
		Name: "GitLab Advisory Database Community",
		URL:  "https://gitlab.com/gitlab-org/advisories-community",
	}
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

func (vs VulnSrc) Name() types.SourceID {
	return source.ID
}

func (vs VulnSrc) Update(dir string) error {
	for t := range ecosystems {
		log.Printf("    Updating GitLab Advisory Database %s...", t)
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
	log.Printf("    Saving GitLab Advisory Database %s...", pkgType)
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

		ecosystem, ok := ecosystems[pkgType]
		if !ok {
			return xerrors.Errorf("failed to get ecosystem: %s", pkgType)
		}
		bucketName := bucket.Name(ecosystem, source.Name)
		if err := vs.dbc.PutDataSource(tx, bucketName, source); err != nil {
			return xerrors.Errorf("failed to put data source: %w", err)
		}

		if err := vs.dbc.PutAdvisoryDetail(tx, glad.Identifier, pkgName, []string{bucketName}, a); err != nil {
			return xerrors.Errorf("failed to save GLAD advisory detail: %w", err)
		}

		// glad's cvss score is taken from NVD
		vuln := types.VulnerabilityDetail{
			ID:          glad.Identifier,
			Severity:    types.SeverityUnknown,
			References:  glad.Urls,
			Title:       glad.Title,
			Description: glad.Description,
		}

		if err := vs.dbc.PutVulnerabilityDetail(tx, glad.Identifier, source.ID, vuln); err != nil {
			return xerrors.Errorf("failed to save GLAD vulnerability detail: %w", err)
		}

		// for optimization
		if err := vs.dbc.PutVulnerabilityID(tx, glad.Identifier); err != nil {
			return xerrors.Errorf("failed to save the vulnerability ID: %w", err)
		}
	}

	return nil
}

func supportedIDs(fileName string) bool {
	for _, prefix := range supportedIDPrefixes {
		if strings.HasPrefix(fileName, prefix) {
			return true
		}
	}
	return false
}
