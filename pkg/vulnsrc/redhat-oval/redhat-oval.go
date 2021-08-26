package redhatoval

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"path/filepath"
	"regexp"
	"strings"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

var (
	redhatDir = filepath.Join("oval", "redhat")

	// the same bucket name as Red Hat Security Data API
	platformFormat = "Red Hat Enterprise Linux %s"

	supportedVersions = []string{"5", "6", "7", "8"}

	// PULP_MANIFEST files prefix
	supportedPlatformFileFormat = "rhel-%s-including-unpatched"

	platformRegexp = regexp.MustCompile(`(Red Hat Enterprise Linux \d) is installed`)
	moduleRegexp   = regexp.MustCompile(`Module\s+(.*)\s+is enabled`)
)

type VulnSrc struct {
	dbc db.Operation
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Name() string {
	return vulnerability.RedHatOVAL
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", redhatDir)

	for _, majorVersion := range supportedVersions {
		versionDir := filepath.Join(rootDir, majorVersion)
		files, err := ioutil.ReadDir(versionDir)
		if err != nil {
			return xerrors.Errorf("unable to get a list of directory entries (%s): %w", versionDir, err)
		}
		for _, f := range files {
			if !f.IsDir() {
				continue
			}

			// TODO: keep it unless CPE is supported
			// RHEL is supported for now
			if f.Name() != fmt.Sprintf(supportedPlatformFileFormat, majorVersion) {
				continue
			}
			if err = vs.update(filepath.Join(versionDir, f.Name())); err != nil {
				return xerrors.Errorf("update error (%s): %w", f.Name(), err)
			}
		}
	}

	return nil
}

func (vs VulnSrc) update(dir string) error {
	log.Printf("    Parsing %s", dir)
	// Parse tests
	tests, err := parseTests(dir)
	if err != nil {
		return xerrors.Errorf("failed to parse tests: %w", err)
	}

	var advisories []RedhatOVAL
	definitionsDir := filepath.Join(dir, "definitions")
	err = utils.FileWalk(definitionsDir, func(r io.Reader, path string) error {
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

	if err = vs.save(advisories, tests); err != nil {
		return xerrors.Errorf("error in Red Hat OVAL save: %w", err)
	}

	return nil
}

func (vs VulnSrc) walkCriterion(cri Criteria, tests map[string]rpmInfoTest) (string, string, []Package) {
	var platform string
	var moduleName string
	var packages []Package

	for _, c := range cri.Criterions {
		// Parse module name
		m := moduleRegexp.FindStringSubmatch(c.Comment)
		if len(m) > 1 && m[1] != "" {
			moduleName = m[1]
			continue
		}

		// Parse platform name
		m = platformRegexp.FindStringSubmatch(c.Comment)
		if len(m) > 1 && m[1] != "" {
			platform = m[1]
			continue
		}

		t, ok := tests[c.TestRef]
		if !ok {
			continue
		}

		// Skip red-def:signature_keyid
		if t.SignatureKeyID.Text != "" {
			continue
		}

		packages = append(packages, Package{
			Name:         t.Name,
			FixedVersion: t.FixedVersion,
		})
	}

	if len(cri.Criterias) == 0 {
		return platform, moduleName, packages
	}

	for _, c := range cri.Criterias {
		p, m, pkgs := vs.walkCriterion(c, tests)
		if p != "" {
			platform = p
		}
		if m != "" {
			moduleName = m
		}
		if len(pkgs) != 0 {
			packages = append(packages, pkgs...)
		}
	}
	return platform, moduleName, packages
}

func (vs VulnSrc) save(advisories []RedhatOVAL, tests map[string]rpmInfoTest) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, advisories, tests)
	})
	if err != nil {
		return xerrors.Errorf("failed batch update: %w", err)
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, advisories []RedhatOVAL, tests map[string]rpmInfoTest) error {
	for _, advisory := range advisories {
		// Skip unaffected vulnerabilities
		if strings.Contains(advisory.ID, "unaffected") {
			continue
		}

		// Insert advisories
		platformName, moduleName, affectedPkgs := vs.walkCriterion(advisory.Criteria, tests)
		for _, affectedPkg := range affectedPkgs {
			// OVAL v2 is missing some unpatched vulnerabilities.
			// They should be fetched from Security Data API unless the issue is addressed.
			if affectedPkg.FixedVersion == "" {
				continue
			}

			pkgName := affectedPkg.Name
			if moduleName != "" {
				// Add modular namespace
				// e.g. nodejs:12::npm
				pkgName = fmt.Sprintf("%s::%s", moduleName, pkgName)
			}

			for _, ref := range advisory.Metadata.References {
				// Skip RHSA-ID
				if ref.Source != "CVE" {
					continue
				}
				advisory := types.Advisory{
					FixedVersion: affectedPkg.FixedVersion,
				}
				if err := vs.dbc.PutAdvisoryDetail(tx, ref.RefID, platformName, pkgName, advisory); err != nil {
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
		return nil, xerrors.Errorf("failed to get Red Hat OVAL advisories: %w", err)
	}
	return advisories, nil
}
