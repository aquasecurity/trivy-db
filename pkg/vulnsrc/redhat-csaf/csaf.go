package redhatcsaf

import (
	"fmt"
	"path/filepath"

	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	redhatoval "github.com/aquasecurity/trivy-db/pkg/vulnsrc/redhat-oval"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	rootBucket  = "Red Hat"
	cpeDir      = "cpe"
	csafDir     = "csaf-vex"
	vulnListDir = "vuln-list-redhat"
)

var (
	source = types.DataSource{
		ID:   vulnerability.RedHatCSAFVEX,
		Name: "Red Hat CSAF VEX",
		URL:  "https://access.redhat.com/security/data/csaf/v2/vex/",
	}

	errUnexpectedRecord = oops.Errorf("unexpected record")
)

// PutInput is the argument passed to the put function (default or custom).
// Custom put implementations (e.g. WithCustomPut) can type-assert adv to *PutInput.
type PutInput struct {
	Bucket      Bucket
	Advisory    Advisory
	CPEList     redhatoval.CPEList
	ReleaseDate string // Advisory's initial release date (YYYY-MM-DD), used by CustomPut for PublishDate
}

type Option func(src *VulnSrc)

// WithCustomPut injects a custom function to write advisories (e.g. for filtering RHEL 10).
// The injected function receives *PutInput when called.
func WithCustomPut(put db.CustomPut) Option {
	return func(src *VulnSrc) {
		src.put = put
	}
}

// WithSkipRepoNVRMappings skips storing repository-to-CPE and NVR-to-CPE mappings.
// Use this when OVAL already stores these mappings and CSAF should not overwrite them.
// This is useful when CSAF runs alongside OVAL (e.g., for RHEL 10 support while OVAL handles RHEL 7-9).
func WithSkipRepoNVRMappings() Option {
	return func(src *VulnSrc) {
		src.skipRepoNVRMappings = true
	}
}

type VulnSrc struct {
	put                 db.CustomPut
	skipRepoNVRMappings bool
	dbc                 db.Operation
	parser              Parser
	aggregator          Aggregator
}

func NewVulnSrc(opts ...Option) VulnSrc {
	src := VulnSrc{
		put:        defaultPut,
		dbc:        db.Config{},
		parser:     NewParser(),
		aggregator: Aggregator{},
	}
	for _, o := range opts {
		o(&src)
	}
	return src
}

func (vs VulnSrc) Name() types.SourceID {
	return vulnerability.RedHatCSAFVEX
}

func (vs VulnSrc) Update(dir string) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.update(tx, dir)
	})
	if err != nil {
		return oops.Wrapf(err, "batch update error")
	}
	return nil
}

func (vs VulnSrc) update(tx *bolt.Tx, dir string) error {
	eb := oops.In("redhat_csaf_vex")

	log.Info("Parsing CSAF VEX...")
	vulnListDir := filepath.Join(dir, vulnListDir)
	if err := vs.parser.Parse(vulnListDir); err != nil {
		return eb.Wrapf(err, "failed to parse CSAF VEX")
	}
	log.Info("Parsed CSAF VEX")

	// Merge CSAF CPEs with existing OVAL CPEs to preserve OVAL indices.
	cpeList, err := vs.mergeCPEList(tx, vs.parser.CPEList())
	if err != nil {
		return eb.Wrapf(err, "failed to merge CPE list")
	}

	log.Info("Inserting mappings...")
	if err := vs.putMappings(tx, cpeList); err != nil {
		return eb.Wrapf(err, "failed to put mappings")
	}

	log.Info("Inserting CSAF VEX...")
	bar := utils.NewProgressBar(vs.parser.AdvisoryNum())
	for bkt, rawEntries := range vs.parser.Advisories() {
		eb = eb.Tags("aggregate").With("module", bkt.Module).With("package", bkt.Name).
			With("vulnerability_id", bkt.VulnerabilityID)

		// Convert RawEntries into final Entries
		entries, err := vs.aggregator.AggregateEntries(rawEntries)
		if err != nil {
			return eb.Wrapf(err, "failed to aggregate entries")
		}

		// Create an advisory containing these entries
		advisory := Advisory{Entries: entries}

		// Store the advisory in the DB (default or custom put)
		input := &PutInput{
			Bucket:      bkt,
			Advisory:    advisory,
			CPEList:     cpeList,
			ReleaseDate: vs.parser.ReleaseDate(bkt.VulnerabilityID),
		}
		if err := vs.put(vs.dbc, tx, input); err != nil {
			return eb.Wrapf(err, "failed to put advisory")
		}
		bar.Increment()
	}
	bar.Finish()

	return nil
}

// mergeCPEList merges the CSAF CPE list with existing OVAL CPEs in the database.
// Existing OVAL CPE indices are preserved, and new CSAF-only CPEs are appended.
func (vs VulnSrc) mergeCPEList(tx *bolt.Tx, csafCPEs redhatoval.CPEList) (redhatoval.CPEList, error) {
	existingCPEs, err := vs.dbc.GetAllRedHatCPEs(tx)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to get existing CPEs")
	}

	if len(existingCPEs) == 0 {
		return csafCPEs, nil
	}

	// Build a set of existing CPE strings and find max index
	existingSet := make(map[string]bool, len(existingCPEs))
	maxIndex := -1
	for idx, cpe := range existingCPEs {
		existingSet[cpe] = true
		if idx > maxIndex {
			maxIndex = idx
		}
	}

	// Start with existing CPEs in order
	merged := make(redhatoval.CPEList, maxIndex+1)
	for idx, cpe := range existingCPEs {
		merged[idx] = cpe
	}

	// Append new CSAF CPEs that don't exist in OVAL
	for _, cpe := range csafCPEs {
		if !existingSet[cpe] {
			merged = append(merged, cpe)
			existingSet[cpe] = true
		}
	}

	log.Info("Merged CPE list", "oval_count", len(existingCPEs), "csaf_count", len(csafCPEs), "merged_count", len(merged))
	return merged, nil
}

// TODO: The CPEList type is the same as redhat-oval since both use the same DB structure.
// When redhat-oval is removed in the future, move the CPEList type definition here.
func (vs VulnSrc) putMappings(tx *bolt.Tx, cpeList redhatoval.CPEList) error {
	// Store the data source
	if err := vs.dbc.PutDataSource(tx, rootBucket, source); err != nil {
		return oops.Wrapf(err, "failed to put data source")
	}

	// Skip repo/NVR mappings if requested (e.g., when OVAL already stores them).
	// This prevents CSAF from overwriting OVAL's correct mappings with indices
	// computed from a different CPE directory.
	if !vs.skipRepoNVRMappings {
		// Store the mapping between repository and CPE names
		for repo, cpes := range vs.parser.RepoToCPE() {
			if err := vs.dbc.PutRedHatRepositories(tx, repo, cpeList.Indices(cpes)); err != nil {
				return oops.With("repo", repo).With("cpes", cpes).Wrapf(err, "repository put error")
			}
		}

		// Store the mapping between NVR and CPE names
		for nvr, cpes := range vs.parser.NVRToCPE() {
			if err := vs.dbc.PutRedHatNVRs(tx, nvr, cpeList.Indices(cpes)); err != nil {
				return oops.With("nvr", nvr).With("cpes", cpes).Wrapf(err, "NVR put error")
			}
		}
	}

	// Store CPE indices (the merged list preserves OVAL indices and appends new CSAF CPEs)
	for i, cpe := range cpeList {
		if err := vs.dbc.PutRedHatCPEs(tx, i, cpe); err != nil {
			return oops.With("cpe", cpe).Wrapf(err, "CPE put error")
		}
	}
	return nil
}

// defaultPut is the default advisory write implementation; can be overridden via WithCustomPut.
func defaultPut(dbc db.Operation, tx *bolt.Tx, adv any) error {
	input, ok := adv.(*PutInput)
	if !ok {
		return oops.Errorf("redhat-csaf put: unexpected type %T", adv)
	}

	for i := range input.Advisory.Entries {
		// Convert CPE names to indices.
		input.Advisory.Entries[i].AffectedCPEIndices = input.CPEList.Indices(input.Advisory.Entries[i].AffectedCPEList)
	}

	vulnID := string(input.Bucket.VulnerabilityID)
	pkgName := input.Bucket.Package.Name
	if input.Bucket.Package.Module != "" {
		// Add modular namespace
		// e.g. nodejs:12::npm
		pkgName = fmt.Sprintf("%s::%s", input.Bucket.Package.Module, pkgName)
	}

	if err := dbc.PutAdvisoryDetail(tx, vulnID, pkgName, []string{rootBucket}, input.Advisory); err != nil {
		return oops.Wrapf(err, "failed to save Red Hat CSAF advisory")
	}
	if err := dbc.PutVulnerabilityID(tx, vulnID); err != nil {
		return oops.Wrapf(err, "failed to put vulnerability ID")
	}
	return nil
}

// Get retrieves advisories for a package.
// TODO: The Get implementation is the same as redhat-oval since both use the same DB structure.
// When redhat-oval is removed in the future, move the Get implementation here.
func (vs VulnSrc) Get(pkgName string, repositories, nvrs []string) ([]types.Advisory, error) {
	return redhatoval.NewVulnSrc().Get(pkgName, repositories, nvrs)
}
