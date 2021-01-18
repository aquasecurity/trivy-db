package redhatoval

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/types"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/utils"
)

const (
	mappingURL = "https://www.redhat.com/security/data/metrics/repository-to-cpe.json"

	// the same bucket name as Red Hat Security Data API
	platformFormat = "Red Hat Enterprise Linux %s"

	rhelFileFormat = "rhel-%s"
)

var (
	redhatDir = filepath.Join("oval", "redhat")

	supportedVersions = []string{"5", "6", "7", "8"}

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

func (vs VulnSrc) Update(dir string) error {
	if err := vs.storeRepositoryCPEMapping(); err != nil {
		return xerrors.Errorf("unable to store the mapping between repositories and CPE names: %w", err)
	}

	rootDir := filepath.Join(dir, "vuln-list", redhatDir)

	for _, majorVersion := range supportedVersions {
		versionDir := filepath.Join(rootDir, majorVersion)
		files, err := ioutil.ReadDir(versionDir)
		if err != nil {
			return xerrors.Errorf("unable to get a list of directory entries (%s): %w", versionDir, err)
		}

		var details []vulnerabilityDetail
		for _, f := range files {
			if !f.IsDir() {
				continue
			}

			// Skip unpatched vulnerabilities until OVAL v2 includes necessary information
			if strings.Contains(f.Name(), "-including-unpatched") {
				continue
			}

			parsedDetails, err := parseOVALStream(filepath.Join(versionDir, f.Name()))
			if err != nil {
				return xerrors.Errorf("failed to parse OVAL stream: %w", err)
			}

			if f.Name() == fmt.Sprintf(rhelFileFormat, majorVersion) {
				for i := range parsedDetails {
					parsedDetails[i].isRHEL = true
				}
			}
			details = append(details, parsedDetails...)
		}

		if err = vs.save(details); err != nil {
			return xerrors.Errorf("save error: %w", err)
		}
	}

	return nil
}

func (vs VulnSrc) storeRepositoryCPEMapping() error {
	resp, err := http.Get(mappingURL)
	if err != nil {
		return xerrors.Errorf("failed to get %s: %w", mappingURL, err)
	}
	defer resp.Body.Close()

	var repositoryToCPE repositoryToCPE
	if err = json.NewDecoder(resp.Body).Decode(&repositoryToCPE); err != nil {
		return xerrors.Errorf("JSON parse error: %w", err)
	}

	return vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		for repo, cpes := range repositoryToCPE.Data {
			if err = vs.dbc.PutRedHatCPEs(tx, repo, cpes.Cpes); err != nil {
				return err
			}
		}
		return nil
	})
}

func (vs VulnSrc) save(details []vulnerabilityDetail) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, details)
	})
	if err != nil {
		return xerrors.Errorf("failed batch update: %w", err)
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, details []vulnerabilityDetail) error {
	advisories := map[bucket]advisory{}
	for _, detail := range details {
		var adv advisory
		if v, ok := advisories[detail.bucket]; ok {
			v.Definitions = append(v.Definitions, detail.definition)
			adv = v
		} else {
			adv = advisory{
				Advisory: types.Advisory{
					// FixedVersion is kept for backward compatibility.
					// By default, FixedVersion should be 0 so that this vulnerability can not detected.
					// The value is replaced by a fixed version of RHEL if it exists.
					FixedVersion: "0",
				},
				Definitions: []Definition{detail.definition},
			}
		}

		if detail.isRHEL {
			adv.Advisory.FixedVersion = detail.definition.FixedVersion
		}
		advisories[detail.bucket] = adv
	}

	for bkt, advisory := range advisories {
		if err := vs.dbc.PutAdvisoryDetail(tx, bkt.cveID, bkt.platform, bkt.pkgName, advisory); err != nil {
			return xerrors.Errorf("failed to save Red Hat CVE-ID: %w", err)
		}
	}

	return nil
}

func (vs VulnSrc) Get(release, pkgName string, repositories []string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, release)
	rawAdvisories, err := vs.dbc.ForEachAdvisory(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("unable to iterate advisories: %w", err)
	}

	var cpes []string
	for _, repo := range repositories {
		res, err := vs.dbc.GetRedHatCPEs(repo)
		if err != nil {
			return nil, err
		}
		cpes = append(cpes, res...)
	}

	var advisories []types.Advisory
	for vulnID, v := range rawAdvisories {
		if len(v) == 0 {
			continue
		}

		advs, err := filterAdvisoriesByCPEs(vulnID, v, cpes)
		if err != nil {
			return nil, err
		}
		advisories = append(advisories, advs...)
	}
	return advisories, nil
}

func filterAdvisoriesByCPEs(vulnID string, raw []byte, cpes []string) ([]types.Advisory, error) {
	var adv advisory
	if err := json.Unmarshal(raw, &adv); err != nil {
		return nil, xerrors.Errorf("failed to unmarshal advisory JSON: %w", err)
	}

	var advisories []types.Advisory

	// CentOS has no CPE information in a container image.
	if len(cpes) == 0 && adv.FixedVersion != "0" {
		advisories = append(advisories, types.Advisory{
			VulnerabilityID: vulnID,
			FixedVersion:    adv.FixedVersion,
		})
	}

	for _, def := range adv.Definitions {
		// When CPE names of the package are included in the affected CPE list of RHSA,
		// the RHSA should be used.
		if utils.HasIntersection(cpes, def.AffectedCPEList) {
			advisories = append(advisories, types.Advisory{
				VulnerabilityID: vulnID,
				VendorID:        def.AdvisoryID,
				FixedVersion:    def.FixedVersion,
			})
		}
	}

	return advisories, nil

}

func parseOVALStream(dir string) ([]vulnerabilityDetail, error) {
	log.Printf("    Parsing %s", dir)
	// Parse tests
	tests, err := parseTests(dir)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse tests: %w", err)
	}

	var advisories []redhatOVAL
	definitionsDir := filepath.Join(dir, "definitions")
	if exists, _ := utils.Exists(definitionsDir); !exists {
		return nil, nil
	}

	err = utils.FileWalk(definitionsDir, func(r io.Reader, path string) error {
		var advisory redhatOVAL
		if err := json.NewDecoder(r).Decode(&advisory); err != nil {
			return xerrors.Errorf("failed to decode Red Hat OVAL JSON: %w", err)
		}
		advisories = append(advisories, advisory)
		return nil
	})

	if err != nil {
		return nil, xerrors.Errorf("error in Red Hat OVAL walk: %w", err)
	}

	return parseAdvisories(advisories, tests), nil
}

func parseAdvisories(advisories []redhatOVAL, tests map[string]rpmInfoTest) []vulnerabilityDetail {
	var details []vulnerabilityDetail
	for _, advisory := range advisories {
		// Skip unaffected vulnerabilities
		if strings.Contains(advisory.ID, "unaffected") {
			continue
		}

		// Insert advisories
		platformName, moduleName, affectedPkgs := walkCriterion(advisory.Criteria, tests)
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

			rhsaID, cveIDs := parseReferences(advisory.Metadata.References)

			for _, cveID := range cveIDs {
				details = append(details, vulnerabilityDetail{
					bucket: bucket{
						cveID:    cveID,
						platform: platformName,
						pkgName:  pkgName,
					},
					definition: Definition{
						FixedVersion:    affectedPkg.FixedVersion,
						AffectedCPEList: advisory.Metadata.Advisory.AffectedCpeList,
						AdvisoryID:      rhsaID,
					},
				})
			}
		}
	}
	return details
}

func walkCriterion(cri criteria, tests map[string]rpmInfoTest) (string, string, []pkg) {
	var platform string
	var moduleName string
	var packages []pkg

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

		packages = append(packages, pkg{
			Name:         t.Name,
			FixedVersion: t.FixedVersion,
		})
	}

	if len(cri.Criterias) == 0 {
		return platform, moduleName, packages
	}

	for _, c := range cri.Criterias {
		p, m, pkgs := walkCriterion(c, tests)
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

func parseReferences(refs []reference) (string, []string) {
	var cveIDs []string
	var rhsaID string
	for _, ref := range refs {
		switch ref.Source {
		case "RHSA":
			rhsaID = ref.RefID
		case "CVE":
			cveIDs = append(cveIDs, ref.RefID)
		}
	}
	return rhsaID, cveIDs
}
