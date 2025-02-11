package glad

import (
	"encoding/json"
	"io"
	"path/filepath"
	"strings"

	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	// GitLab Advisory Database
	gladDir = "glad"

	// cf. https://gitlab.com/gitlab-org/security-products/gemnasium-db/-/tree/e4176fff52c027165ae5a79f5b1193090e2fbef0#package-slug-and-package-name
	Conan packageType = "conan"
)

var (
	supportedIDPrefixes = []string{
		"CVE",
		"GHSA",
		"GMS",
	}

	// Mapping between GLAD slug and Trivy ecosystem
	ecosystems = map[packageType]types.Ecosystem{
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
	dbc    db.Operation
	logger *log.Logger
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc:    db.Config{},
		logger: log.WithPrefix("glad"),
	}
}

func (vs VulnSrc) Name() types.SourceID {
	return source.ID
}

func (vs VulnSrc) Update(dir string) error {
	eb := oops.In("glad")
	for t := range ecosystems {
		vs.logger.Info("Updating GitLab Advisory Database",
			log.String("type", cases.Title(language.English).String(string(t))))

		rootDir := filepath.Join(dir, "vuln-list", gladDir, string(t))
		eb := eb.With("root_dir", rootDir)

		if err := vs.update(t, rootDir); err != nil {
			return eb.Wrapf(err, "update error")
		}
	}
	return nil
}

func (vs VulnSrc) update(pkgType packageType, rootDir string) error {
	eb := oops.With("package_type", pkgType)
	var glads []Advisory
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		if !supportedIDs(filepath.Base(path)) {
			return nil
		}
		eb := eb.With("file_path", path)

		var glad Advisory
		if err := json.NewDecoder(r).Decode(&glad); err != nil {
			return eb.Wrapf(err, "json decode error")
		}

		glads = append(glads, glad)
		return nil
	})
	if err != nil {
		return eb.Wrapf(err, "walk error")
	}

	if err = vs.save(pkgType, glads); err != nil {
		return eb.Wrapf(err, "save error")
	}

	return nil
}

func (vs VulnSrc) save(pkgType packageType, glads []Advisory) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, pkgType, glads)
	})
	if err != nil {
		return oops.Wrapf(err, "batch update error")
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, pkgType packageType, glads []Advisory) error {
	for _, glad := range glads {
		a := types.Advisory{
			VulnerableVersions: []string{glad.AffectedRange},
			PatchedVersions:    glad.FixedVersions,
		}
		eb := oops.With("vuln_id", glad.Identifier).With("slug", glad.PackageSlug)

		// e.g. "go/github.com/go-ldap/ldap" => "go", "github.com/go-ldap/ldap"
		ss := strings.SplitN(glad.PackageSlug, "/", 2)
		if len(ss) < 2 {
			return eb.Errorf("failed to parse package slug")
		}

		pkgName := ss[1]
		ecosystem, ok := ecosystems[pkgType]
		if !ok {
			return eb.Errorf("failed to get ecosystem: %s", pkgType)
		}
		bucketName := bucket.Name(ecosystem, source.Name)
		eb = eb.With("ecosystem", ecosystem)

		if err := vs.dbc.PutDataSource(tx, bucketName, source); err != nil {
			return eb.Wrapf(err, "failed to put data source")
		}

		if err := vs.dbc.PutAdvisoryDetail(tx, glad.Identifier, pkgName, []string{bucketName}, a); err != nil {
			return eb.Wrapf(err, "failed to save advisory")
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
			return eb.Wrapf(err, "failed to save vulnerability detail")
		}

		// for optimization
		if err := vs.dbc.PutVulnerabilityID(tx, glad.Identifier); err != nil {
			return eb.Wrapf(err, "failed to save vulnerability ID")
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
