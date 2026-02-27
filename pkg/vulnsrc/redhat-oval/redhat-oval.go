package redhatoval

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/utils/ints"
	ustrings "github.com/aquasecurity/trivy-db/pkg/utils/strings"
	bucketpkg "github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

var (
	ovalDir     = "oval"
	cpeDir      = "cpe"
	vulnListDir = "vuln-list-redhat"

	moduleRegexp = regexp.MustCompile(`Module\s+(.*)\s+is enabled`)

	source = types.DataSource{
		ID:   vulnerability.RedHat,
		Name: "Red Hat",
		URL:  "https://access.redhat.com/security/cve/",
	}
)

type VulnSrc struct {
	dbc    db.Operation
	logger *log.Logger
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc:    db.Config{},
		logger: log.WithPrefix("redhat-oval"),
	}
}

func (vs VulnSrc) Name() types.SourceID {
	return source.ID
}

func (vs VulnSrc) Update(dir string) error {
	eb := oops.In("redhat").Tags("oval")
	uniqCPEs := CPEMap{}

	repoToCPE, err := vs.parseRepositoryCpeMapping(dir, uniqCPEs)
	if err != nil {
		return eb.Wrapf(err, "unable to store the mapping between repositories and CPE names")
	}

	nvrToCPE, err := vs.parseNvrCpeMapping(dir, uniqCPEs)
	if err != nil {
		return eb.Wrapf(err, "unable to store the mapping between NVR and CPE names")
	}

	// List version directories
	rootDir := filepath.Join(dir, vulnListDir, ovalDir)
	eb = eb.With("root_dir", rootDir)

	versions, err := os.ReadDir(rootDir)
	if err != nil {
		return eb.Wrapf(err, "unable to list directory entries")
	}

	advisories := map[bucket]Advisory{}
	for _, ver := range versions {
		versionDir := filepath.Join(rootDir, ver.Name())
		eb := eb.With("version_dir", versionDir)

		streams, err := os.ReadDir(versionDir)
		if err != nil {
			return eb.Wrapf(err, "unable to get a list of directory entries")
		}

		for _, f := range streams {
			if !f.IsDir() {
				continue
			}
			eb := eb.With("stream_dir", f.Name())

			definitions, err := vs.parseOVALStream(filepath.Join(versionDir, f.Name()), uniqCPEs)
			if err != nil {
				return eb.Wrapf(err, "failed to parse OVAL stream")
			}

			advisories = vs.mergeAdvisories(advisories, definitions)
		}
	}

	if err = vs.save(repoToCPE, nvrToCPE, advisories, uniqCPEs); err != nil {
		return eb.Wrapf(err, "save error")
	}

	return nil
}

func (vs VulnSrc) parseRepositoryCpeMapping(dir string, uniqCPEs CPEMap) (map[string][]string, error) {
	filePath := filepath.Join(dir, vulnListDir, cpeDir, "repository-to-cpe.json")
	eb := oops.With("file_path", filePath)

	f, err := os.Open(filePath)
	if err != nil {
		return nil, eb.Wrapf(err, "file open error")
	}
	defer f.Close()

	var repoToCPE map[string][]string
	if err = json.NewDecoder(f).Decode(&repoToCPE); err != nil {
		return nil, eb.Wrapf(err, "json parse error")
	}

	for _, cpes := range repoToCPE {
		updateCPEs(cpes, uniqCPEs)
	}

	return repoToCPE, nil
}

func (vs VulnSrc) parseNvrCpeMapping(dir string, uniqCPEs CPEMap) (map[string][]string, error) {
	filePath := filepath.Join(dir, vulnListDir, cpeDir, "nvr-to-cpe.json")
	eb := oops.With("file_path", filePath)

	f, err := os.Open(filePath)
	if err != nil {
		return nil, eb.Wrapf(err, "file open error")
	}
	defer f.Close()

	nvrToCpe := map[string][]string{}
	if err = json.NewDecoder(f).Decode(&nvrToCpe); err != nil {
		return nil, eb.Wrapf(err, "json parse error")
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
				// New advisory should contain a single fixed version and list of arches.
				if old.Entries[i].FixedVersion == def.Entry.FixedVersion && old.Entries[i].Status == def.Entry.Status &&
					slices.Equal(old.Entries[i].Arches, def.Entry.Arches) && slices.Equal(old.Entries[i].Cves, def.Entry.Cves) {
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

func (vs VulnSrc) save(repoToCpe, nvrToCpe map[string][]string, advisories map[bucket]Advisory, uniqCPEs CPEMap) error {
	cpeList := uniqCPEs.List()
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		if err := vs.dbc.PutDataSource(tx, bucketpkg.NewRedHat("").Name(), source); err != nil {
			return oops.Wrapf(err, "failed to put data source")
		}

		// Store the mapping between repository and CPE names
		for repo, cpes := range repoToCpe {
			if err := vs.dbc.PutRedHatRepositories(tx, repo, cpeList.Indices(cpes)); err != nil {
				return oops.Wrapf(err, "repository put error")
			}
		}

		// Store the mapping between NVR and CPE names
		for nvr, cpes := range nvrToCpe {
			if err := vs.dbc.PutRedHatNVRs(tx, nvr, cpeList.Indices(cpes)); err != nil {
				return oops.Wrapf(err, "NVR put error")
			}
		}

		//  Store advisories
		for bkt, advisory := range advisories {
			for i := range advisory.Entries {
				// Convert CPE names to indices.
				advisory.Entries[i].AffectedCPEIndices = cpeList.Indices(advisory.Entries[i].AffectedCPEList)
			}

			if err := vs.dbc.PutAdvisoryDetail(tx, bkt.vulnID, bkt.pkgName, []string{bucketpkg.NewRedHat("").Name()}, advisory); err != nil {
				return oops.Wrapf(err, "failed to save Red Hat OVAL advisory")
			}

			if err := vs.dbc.PutVulnerabilityID(tx, bkt.vulnID); err != nil {
				return oops.Wrapf(err, "failed to put vulnerability ID")
			}
		}

		// Store CPE indices for debug information
		for i, cpe := range cpeList {
			if err := vs.dbc.PutRedHatCPEs(tx, i, cpe); err != nil {
				return oops.Wrapf(err, "cpe put error")
			}
		}

		return nil
	})
	if err != nil {
		return oops.Wrapf(err, "batch update error")
	}
	return nil
}

func (vs VulnSrc) cpeIndices(repositories, nvrs []string) ([]int, error) {
	var cpeIndices []int
	for _, repo := range repositories {
		results, err := vs.dbc.RedHatRepoToCPEs(repo)
		if err != nil {
			return nil, oops.With("repo", repo).Wrapf(err, "unable to convert repositories to CPEs")
		}
		cpeIndices = append(cpeIndices, results...)
	}

	for _, nvr := range nvrs {
		results, err := vs.dbc.RedHatNVRToCPEs(nvr)
		if err != nil {
			return nil, oops.With("nvr", nvr).Wrapf(err, "unable to convert repositories to CPEs")
		}
		cpeIndices = append(cpeIndices, results...)
	}

	return ints.Unique(cpeIndices), nil
}

func (vs VulnSrc) Get(pkgName string, repositories, nvrs []string) ([]types.Advisory, error) {
	eb := oops.In("redhat").Tags("oval").With("package_name", pkgName).With("repositories", repositories).With("nvrs", nvrs)
	cpeIndices, err := vs.cpeIndices(repositories, nvrs)
	if err != nil {
		return nil, eb.Wrapf(err, "cpe convert error")
	}

	if len(cpeIndices) == 0 {
		return nil, eb.Errorf("unable to find CPE indices. See https://github.com/aquasecurity/trivy-db/issues/435 for details")
	}

	rawAdvisories, err := vs.dbc.ForEachAdvisory([]string{bucketpkg.NewRedHat("").Name()}, pkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "unable to iterate advisories")
	}

	var advisories []types.Advisory
	for vulnID, v := range rawAdvisories {
		var adv Advisory
		if err = json.Unmarshal(v.Content, &adv); err != nil {
			return nil, eb.Wrapf(err, "failed to unmarshal advisory JSON")
		}

		for _, entry := range adv.Entries {
			if !ints.HasIntersection(cpeIndices, entry.AffectedCPEIndices) {
				continue
			}

			for _, cve := range entry.Cves {
				advisory := types.Advisory{
					Severity:     cve.Severity,
					FixedVersion: entry.FixedVersion,
					Arches:       entry.Arches,
					Status:       entry.Status,
					DataSource:   &v.Source,
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

func (vs VulnSrc) parseOVALStream(dir string, uniqCPEs CPEMap) (map[bucket]Definition, error) {
	vs.logger.Info("Parsing OVAL stream", log.DirPath(dir))

	// Parse tests
	tests, err := parseTests(dir)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to parse ovalTests")
	}

	var advisories []redhatOVAL
	definitionsDir := filepath.Join(dir, "definitions")
	if exists, _ := utils.Exists(definitionsDir); !exists {
		return nil, nil
	}

	eb := oops.With("definitions_dir", definitionsDir)
	err = utils.FileWalk(definitionsDir, func(r io.Reader, path string) error {
		var definition redhatOVAL
		if err := json.NewDecoder(r).Decode(&definition); err != nil {
			return eb.With("file_path", path).Wrapf(err, "json decode error")
		}
		advisories = append(advisories, definition)
		return nil
	})

	if err != nil {
		return nil, eb.Wrapf(err, "oval walk error")
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
		affectedPkgs := walkCriterion(advisory.Criteria, tests)
		for _, affectedPkg := range affectedPkgs {
			pkgName := affectedPkg.Name
			if affectedPkg.Module != "" {
				// Add modular namespace
				// e.g. nodejs:12::npm
				pkgName = fmt.Sprintf("%s::%s", affectedPkg.Module, pkgName)
			}

			rhsaID := vendorID(advisory.Metadata.References)

			var cveEntries []CveEntry
			for _, cve := range advisory.Metadata.Advisory.Cves {
				cveEntries = append(cveEntries, CveEntry{
					ID:       cve.CveID,
					Severity: severityFromImpact(cve.Impact),
				})
			}
			sort.Slice(cveEntries, func(i, j int) bool {
				return cveEntries[i].ID < cveEntries[j].ID
			})

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
						Arches:          affectedPkg.Arches,

						// The status is obviously "fixed" when there is a patch.
						// To keep the database size small, we don't store the status for patched vulns.
						// Status:		  StatusFixed,
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
							Arches:          affectedPkg.Arches,
							Status:          newStatus(advisory.Metadata.Advisory.Affected.Resolution.State),
						},
					}
				}
			}
		}

		updateCPEs(advisory.Metadata.Advisory.AffectedCpeList, uniqCPEs)
	}
	return defs
}

// walkCriterion recursively walks the OVAL criteria tree and extracts affected packages.
// It handles modular packages by associating each package with its module context.
//
// OVAL structure for modular packages:
//
//	Criteria (AND)
//	├── Criterion: "Module nodejs:20 is enabled"   ← module condition at this level
//	└── Criterias                                   ← packages are always nested
//	    └── Criteria (AND)
//	        ├── Criterion: "nodejs-full-i18n is installed"
//	        └── Criterion: "nodejs-full-i18n is signed..."
//
// When multiple modules exist at the same level (e.g., nodejs:20 OR nodejs:22),
// each module's packages are processed separately and tagged with their respective module.
//
//nolint:misspell
func walkCriterion(cri criteria, tests map[string]rpmInfoTest) []pkg {
	var moduleName string
	var packages []pkg

	// First pass: extract module name and packages from current level Criterions
	for _, c := range cri.Criterions {
		// Check if this criterion defines a module (e.g., "Module nodejs:20 is enabled")
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

		var arches []string
		if t.Arch != "" {
			arches = strings.Split(t.Arch, "|") // affected arches are merged with '|'(e.g. 'aarch64|ppc64le|x86_64')
			sort.Strings(arches)
		}

		packages = append(packages, pkg{
			Name:         t.Name,
			FixedVersion: t.FixedVersion,
			Arches:       arches,
		})
	}

	if len(cri.Criterias) == 0 {
		return packages
	}

	// Second pass: recursively process nested Criterias
	for _, c := range cri.Criterias {
		pkgs := walkCriterion(c, tests)

		// Apply current module to nested packages that don't have one.
		// This propagates the module context down the tree.
		for i := range pkgs {
			if pkgs[i].Module == "" {
				pkgs[i].Module = moduleName
			}
		}

		packages = append(packages, pkgs...)
	}
	return packages
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

func newStatus(s string) types.Status {
	switch strings.ToLower(s) {
	case "affected", "fix deferred":
		return types.StatusAffected
	case "under investigation":
		return types.StatusUnderInvestigation
	case "will not fix":
		return types.StatusWillNotFix
	case "out of support scope":
		return types.StatusEndOfLife
	}
	return types.StatusUnknown
}
