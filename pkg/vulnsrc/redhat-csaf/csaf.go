package redhatcsaf

import (
	"fmt"
	"iter"
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

// Store customizes how CSAF VEX data is persisted to the database.
// The default implementation (defaultStore) is used for OSS.
type Store interface {
	// PutMappings writes CPE-related mappings to the database and returns
	// the CPE list to use for advisory writes.
	PutMappings(dbc db.Operation, tx *bolt.Tx, input *MappingsInput) (redhatoval.CPEList, error)

	// Put writes an advisory to the database.
	Put(dbc db.Operation, tx *bolt.Tx, input *PutInput) error
}

// MappingsInput contains the data needed to write CPE-related mappings.
type MappingsInput struct {
	CPEList   redhatoval.CPEList
	RepoToCPE iter.Seq2[string, []string]
	NVRToCPE  iter.Seq2[string, []string]
}

type PutInput struct {
	Bucket   Bucket
	Advisory Advisory
	CPEList  redhatoval.CPEList
}

// defaultStore is the OSS default implementation of Store.
type defaultStore struct{}

// PutMappings writes all mappings (repo-to-CPE, NVR-to-CPE, CPE indices) and returns
// the input CPE list unchanged.
//
// TODO: The CPEList type is the same as redhat-oval since both use the same DB structure.
// When redhat-oval is removed in the future, move the CPEList type definition here.
func (defaultStore) PutMappings(dbc db.Operation, tx *bolt.Tx, input *MappingsInput) (redhatoval.CPEList, error) {
	// Store the mapping between repository and CPE names
	for repo, cpes := range input.RepoToCPE {
		if err := dbc.PutRedHatRepositories(tx, repo, input.CPEList.Indices(cpes)); err != nil {
			return nil, oops.With("repo", repo).With("cpes", cpes).Wrapf(err, "repository put error")
		}
	}

	// Store the mapping between NVR and CPE names
	for nvr, cpes := range input.NVRToCPE {
		if err := dbc.PutRedHatNVRs(tx, nvr, input.CPEList.Indices(cpes)); err != nil {
			return nil, oops.With("nvr", nvr).With("cpes", cpes).Wrapf(err, "NVR put error")
		}
	}

	// Store CPE indices for debug information
	for i, cpe := range input.CPEList {
		if err := dbc.PutRedHatCPEs(tx, i, cpe); err != nil {
			return nil, oops.With("cpe", cpe).Wrapf(err, "CPE put error")
		}
	}

	return input.CPEList, nil
}

// Put converts CPE names to indices and writes the advisory via PutAdvisoryDetail.
func (defaultStore) Put(dbc db.Operation, tx *bolt.Tx, input *PutInput) error {
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

type Option func(src *VulnSrc)

// WithStore injects a custom Store implementation (e.g., for premium).
func WithStore(store Store) Option {
	return func(src *VulnSrc) {
		src.store = store
	}
}

type VulnSrc struct {
	store      Store
	dbc        db.Operation
	parser     Parser
	aggregator Aggregator
}

func NewVulnSrc(opts ...Option) VulnSrc {
	src := VulnSrc{
		store:      defaultStore{},
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

	// Store the data source
	if err := vs.dbc.PutDataSource(tx, rootBucket, source); err != nil {
		return eb.Wrapf(err, "failed to put data source")
	}

	log.Info("Inserting mappings...")
	cpeList, err := vs.store.PutMappings(vs.dbc, tx, &MappingsInput{
		CPEList:   vs.parser.CPEList(),
		RepoToCPE: vs.parser.RepoToCPE(),
		NVRToCPE:  vs.parser.NVRToCPE(),
	})
	if err != nil {
		return eb.Wrapf(err, "failed to put mappings")
	}

	log.Info("Inserting CSAF VEX...")
	bar := utils.NewProgressBar(vs.parser.AdvisoryNum())
	for bkt, rawEntries := range vs.parser.Advisories() {
		eb = eb.Tags("aggregate").With("module", bkt.Module).With("package", bkt.Name).
			With("vulnerability_id", bkt.VulnerabilityID)

		entries, err := vs.aggregator.AggregateEntries(rawEntries)
		if err != nil {
			return eb.Wrapf(err, "failed to aggregate entries")
		}

		advisory := Advisory{Entries: entries}

		input := &PutInput{
			Bucket:   bkt,
			Advisory: advisory,
			CPEList:  cpeList,
		}
		if err := vs.store.Put(vs.dbc, tx, input); err != nil {
			return eb.Wrapf(err, "failed to put advisory")
		}
		bar.Increment()
	}
	bar.Finish()

	return nil
}

// Get retrieves advisories for a package.
// TODO: The Get implementation is the same as redhat-oval since both use the same DB structure.
// When redhat-oval is removed in the future, move the Get implementation here.
func (vs VulnSrc) Get(pkgName string, repositories, nvrs []string) ([]types.Advisory, error) {
	return redhatoval.NewVulnSrc().Get(pkgName, repositories, nvrs)
}
