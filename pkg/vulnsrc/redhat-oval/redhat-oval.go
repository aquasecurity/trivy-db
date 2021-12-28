package redhatoval

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/utils/ints"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	ustrings "github.com/aquasecurity/trivy-db/pkg/utils/strings"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	mappingURL = "https://www.redhat.com/security/data/metrics/repository-to-cpe.json"

	rootBucket = "Red Hat"
)

var (
	redhatDir = filepath.Join("oval", "redhat")

	moduleRegexp = regexp.MustCompile(`Module\s+(.*)\s+is enabled`)
)

type VulnSrc struct {
	dbc        db.Operation
	mappingURL string
}

type Option func(c *VulnSrc)

func WithMappingURL(url string) Option {
	return func(vs *VulnSrc) {
		vs.mappingURL = url
	}
}

func NewVulnSrc(opts ...Option) VulnSrc {
	vs := &VulnSrc{
		dbc:        db.Config{},
		mappingURL: mappingURL,
	}
	for _, opt := range opts {
		opt(vs)
	}

	return *vs
}

func (vs VulnSrc) Name() string {
	return vulnerability.RedHatOVAL
}

func (vs VulnSrc) Update(dir string) error {
	uniqCPEs := CPEMap{}

	repoToCPE, err := vs.parseRepositoryCpeMapping(uniqCPEs)
	if err != nil {
		return xerrors.Errorf("unable to store the mapping between repositories and CPE names: %w", err)
	}

	nvrToCPE, err := vs.parseNvrCpeMapping(uniqCPEs)
	if err != nil {
		return xerrors.Errorf("unable to store the mapping between NVR and CPE names: %w", err)
	}

	// List version directories
	rootDir := filepath.Join(dir, "vuln-list", redhatDir)
	versions, err := os.ReadDir(rootDir)
	if err != nil {
		return xerrors.Errorf("unable to list directory entries (%s): %w", rootDir, err)
	}

	advisories := map[bucket]Advisory{}
	for _, ver := range versions {
		versionDir := filepath.Join(rootDir, ver.Name())
		streams, err := os.ReadDir(versionDir)
		if err != nil {
			return xerrors.Errorf("unable to get a list of directory entries (%s): %w", versionDir, err)
		}

		for _, f := range streams {
			if !f.IsDir() {
				continue
			}

			definitions, err := parseOVALStream(filepath.Join(versionDir, f.Name()), uniqCPEs)
			if err != nil {
				return xerrors.Errorf("failed to parse OVAL stream: %w", err)
			}

			advisories = vs.mergeAdvisories(advisories, definitions)

		}
	}

	if err = vs.save(repoToCPE, nvrToCPE, advisories, uniqCPEs); err != nil {
		return xerrors.Errorf("save error: %w", err)
	}

	return nil
}

func (vs VulnSrc) parseRepositoryCpeMapping(uniqCPEs CPEMap) (repositoryToCPE, error) {
	resp, err := http.Get(vs.mappingURL)
	if err != nil {
		return repositoryToCPE{}, xerrors.Errorf("failed to get %s: %w", mappingURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return repositoryToCPE{}, xerrors.Errorf("Red Hat API (%s) returns %d", mappingURL, resp.StatusCode)
	}

	var repoToCPE repositoryToCPE
	if err = json.NewDecoder(resp.Body).Decode(&repoToCPE); err != nil {
		return repositoryToCPE{}, xerrors.Errorf("JSON parse error: %w", err)
	}

	for _, cpes := range repoToCPE.Data {
		updateCPEs(cpes.Cpes, uniqCPEs)
	}

	return repoToCPE, nil
}

func (vs VulnSrc) parseNvrCpeMapping(uniqCPEs CPEMap) (map[string][]string, error) {
	f, err := os.Open("mapping.json")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	nvrToCpe := map[string][]string{}
	if err = json.NewDecoder(f).Decode(&nvrToCpe); err != nil {
		return nil, xerrors.Errorf("JSON parse error: %w", err)
	}

	for _, cpes := range nvrToCpe {
		updateCPEs(cpes, uniqCPEs)
	}
	return nvrToCpe, nil
}

func (vs VulnSrc) mergeAdvisories(advisories map[bucket]Advisory, defs map[bucket]Definition) map[bucket]Advisory {
	for bkt, def := range defs {
		if old, ok := advisories[bkt]; ok {
			found := false
			for i := range old.Entries {
				// New advisory should contain a single fixed version.
				if old.Entries[i].FixedVersion == def.Entry.FixedVersion {
					found = true
					old.Entries[i].AffectedCPEList = ustrings.Merge(old.Entries[i].AffectedCPEList, def.Entry.AffectedCPEList)
				}
			}
			if !found {
				old.Entries = append(old.Entries, def.Entry)
			}
			advisories[bkt] = old
		} else {
			advisories[bkt] = Advisory{
				Entries: []Entry{def.Entry},
			}
		}
	}

	return advisories
}

func (vs VulnSrc) save(repoToCpe repositoryToCPE, nvrToCpe map[string][]string, advisories map[bucket]Advisory, uniqCPEs CPEMap) error {
	cpeList := uniqCPEs.List()
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		// Store the mapping between repository and CPE names
		for repo, cpes := range repoToCpe.Data {
			if err := vs.dbc.PutRedHatRepositories(tx, repo, cpeList.Indices(cpes.Cpes)); err != nil {
				return xerrors.Errorf("repository put error: %w", err)
			}
		}

		// Store the mapping between NVR and CPE names
		for nvr, cpes := range nvrToCpe {
			if err := vs.dbc.PutRedHatNVRs(tx, nvr, cpeList.Indices(cpes)); err != nil {
				return xerrors.Errorf("NVR put error: %w", err)
			}
		}

		//  Store advisories
		for bkt, advisory := range advisories {
			for i := range advisory.Entries {
				// Convert CPE names to indices.
				advisory.Entries[i].AffectedCPEIndices = cpeList.Indices(advisory.Entries[i].AffectedCPEList)
			}

			if err := vs.dbc.PutAdvisoryDetail(tx, bkt.vulnID, bkt.pkgName, []string{rootBucket}, advisory); err != nil {
				return xerrors.Errorf("failed to save Red Hat OVAL advisory: %w", err)
			}

			if err := vs.dbc.PutSeverity(tx, bkt.vulnID, types.SeverityUnknown); err != nil {
				return xerrors.Errorf("failed to put severity: %w", err)
			}
		}

		// Store CPE indices for debug information
		for i, cpe := range cpeList {
			if err := vs.dbc.PutRedHatCPEs(tx, i, cpe); err != nil {
				return xerrors.Errorf("CPE put error: %w", err)
			}
		}

		return nil
	})
	if err != nil {
		return xerrors.Errorf("batch update error: %w", err)
	}
	return nil
}

func (vs VulnSrc) cpeIndices(repositories, nvrs []string) ([]int, error) {
	var cpeIndices []int
	for _, repo := range repositories {
		results, err := vs.dbc.RedHatRepoToCPEs(repo)
		if err != nil {
			return nil, xerrors.Errorf("unable to convert repositories to CPEs: %w", err)
		}
		cpeIndices = append(cpeIndices, results...)
	}

	for _, nvr := range nvrs {
		results, err := vs.dbc.RedHatNVRToCPEs(nvr)
		if err != nil {
			return nil, xerrors.Errorf("unable to convert repositories to CPEs: %w", err)
		}
		cpeIndices = append(cpeIndices, results...)
	}

	return ints.Unique(cpeIndices), nil
}

func (vs VulnSrc) Get(pkgName string, repositories, nvrs []string) ([]types.Advisory, error) {
	cpeIndices, err := vs.cpeIndices(repositories, nvrs)
	if err != nil {
		return nil, xerrors.Errorf("CPE convert error: %w", err)
	}

	rawAdvisories, err := vs.dbc.ForEachAdvisory([]string{rootBucket}, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("unable to iterate advisories: %w", err)
	}

	var advisories []types.Advisory
	for vulnID, v := range rawAdvisories {
		if len(v) == 0 {
			continue
		}

		var adv Advisory
		if err = json.Unmarshal(v, &adv); err != nil {
			return nil, xerrors.Errorf("failed to unmarshal advisory JSON: %w", err)
		}

		for _, entry := range adv.Entries {
			if !ints.HasIntersection(cpeIndices, entry.AffectedCPEIndices) {
				continue
			}

			for _, cve := range entry.Cves {
				advisory := types.Advisory{
					Severity:     cve.Severity,
					FixedVersion: entry.FixedVersion,
				}

				if strings.HasPrefix(vulnID, "CVE-") {
					advisory.VulnerabilityID = vulnID
				} else {
					advisory.VulnerabilityID = cve.ID
					advisory.VendorIDs = []string{vulnID}
				}

				advisories = append(advisories, advisory)
			}
		}
	}

	return advisories, nil
}

func parseOVALStream(dir string, uniqCPEs CPEMap) (map[bucket]Definition, error) {
	log.Printf("    Parsing %s", dir)

	// Parse tests
	tests, err := parseTests(dir)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse ovalTests: %w", err)
	}

	var advisories []redhatOVAL
	definitionsDir := filepath.Join(dir, "definitions")
	if exists, _ := utils.Exists(definitionsDir); !exists {
		return nil, nil
	}

	err = utils.FileWalk(definitionsDir, func(r io.Reader, path string) error {
		var definition redhatOVAL
		if err := json.NewDecoder(r).Decode(&definition); err != nil {
			return xerrors.Errorf("failed to decode %s: %w", path, err)
		}
		advisories = append(advisories, definition)
		return nil
	})

	if err != nil {
		return nil, xerrors.Errorf("Red Hat OVAL walk error: %w", err)
	}

	return parseDefinitions(advisories, tests, uniqCPEs), nil
}

func parseDefinitions(advisories []redhatOVAL, tests map[string]rpmInfoTest, uniqCPEs CPEMap) map[bucket]Definition {
	defs := map[bucket]Definition{}

	for _, advisory := range advisories {
		// Skip unaffected vulnerabilities
		if strings.Contains(advisory.ID, "unaffected") {
			continue
		}

		// Parse criteria
		moduleName, affectedPkgs := walkCriterion(advisory.Criteria, tests)
		for _, affectedPkg := range affectedPkgs {
			pkgName := affectedPkg.Name
			if moduleName != "" {
				// Add modular namespace
				// e.g. nodejs:12::npm
				pkgName = fmt.Sprintf("%s::%s", moduleName, pkgName)
			}

			rhsaID := vendorID(advisory.Metadata.References)

			var cveEntries []CveEntry
			for _, cve := range advisory.Metadata.Advisory.Cves {
				cveEntries = append(cveEntries, CveEntry{
					ID:       cve.CveID,
					Severity: severityFromImpact(cve.Impact),
				})
			}

			if rhsaID != "" { // For patched vulnerabilities
				bkt := bucket{
					pkgName: pkgName,
					vulnID:  rhsaID,
				}
				defs[bkt] = Definition{
					Entry: Entry{
						Cves:            cveEntries,
						FixedVersion:    affectedPkg.FixedVersion,
						AffectedCPEList: advisory.Metadata.Advisory.AffectedCpeList,
					},
				}
			} else { // For unpatched vulnerabilities
				for _, cve := range cveEntries {
					bkt := bucket{
						pkgName: pkgName,
						vulnID:  cve.ID,
					}
					defs[bkt] = Definition{
						Entry: Entry{
							Cves: []CveEntry{
								{
									Severity: cve.Severity,
								},
							},
							FixedVersion:    affectedPkg.FixedVersion,
							AffectedCPEList: advisory.Metadata.Advisory.AffectedCpeList,
						},
					}
				}
			}
		}

		updateCPEs(advisory.Metadata.Advisory.AffectedCpeList, uniqCPEs)
	}

	return defs
}

func walkCriterion(cri criteria, tests map[string]rpmInfoTest) (string, []pkg) {
	var moduleName string
	var packages []pkg

	for _, c := range cri.Criterions {
		// Parse module name
		m := moduleRegexp.FindStringSubmatch(c.Comment)
		if len(m) > 1 && m[1] != "" {
			moduleName = m[1]
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
		return moduleName, packages
	}

	for _, c := range cri.Criterias {
		m, pkgs := walkCriterion(c, tests)
		if m != "" {
			moduleName = m
		}
		if len(pkgs) != 0 {
			packages = append(packages, pkgs...)
		}
	}
	return moduleName, packages
}

func updateCPEs(cpes []string, uniqCPEs CPEMap) {
	for _, cpe := range cpes {
		cpe = strings.TrimSpace(cpe)
		if cpe == "" {
			continue
		}
		uniqCPEs.Add(cpe)
	}
}

func vendorID(refs []reference) string {
	for _, ref := range refs {
		switch ref.Source {
		case "RHSA", "RHBA":
			return ref.RefID
		}
	}
	return ""
}

func severityFromImpact(sev string) types.Severity {
	switch strings.ToLower(sev) {
	case "low":
		return types.SeverityLow
	case "moderate":
		return types.SeverityMedium
	case "important":
		return types.SeverityHigh
	case "critical":
		return types.SeverityCritical
	}
	return types.SeverityUnknown
}
