package redhatcsaf

import (
	"fmt"
	"path/filepath"

	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

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

	errUnexpectedRecord = xerrors.New("unexpected record")
)

type VulnSrc struct {
	dbc        db.Operation
	parser     Parser
	aggregator Aggregator
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc:        db.Config{},
		parser:     NewParser(),
		aggregator: Aggregator{},
	}
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

	cpeList := vs.parser.CPEList()

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

		// Store the advisory in the DB
		if err := vs.putAdvisory(tx, bkt, advisory, cpeList); err != nil {
			return eb.Wrapf(err, "failed to put advisory")
		}
		bar.Increment()
	}
	bar.Finish()

	return nil
}

// TODO: The CPEList type is the same as redhat-oval since both use the same DB structure.
// When redhat-oval is removed in the future, move the CPEList type definition here.
func (vs VulnSrc) putMappings(tx *bolt.Tx, cpeList redhatoval.CPEList) error {
	// Store the data source
	if err := vs.dbc.PutDataSource(tx, rootBucket, source); err != nil {
		return xerrors.Errorf("failed to put data source: %w", err)
	}

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

	// Store CPE indices for debug information
	for i, cpe := range cpeList {
		if err := vs.dbc.PutRedHatCPEs(tx, i, cpe); err != nil {
			return oops.With("cpe", cpe).Wrapf(err, "CPE put error")
		}
	}
	return nil
}

func (vs VulnSrc) putAdvisory(tx *bolt.Tx, bkt Bucket, adv Advisory, cpeList redhatoval.CPEList) error {
	for i := range adv.Entries {
		// Convert CPE names to indices.
		adv.Entries[i].AffectedCPEIndices = cpeList.Indices(adv.Entries[i].AffectedCPEList)
	}

	vulnID := string(bkt.VulnerabilityID)
	pkgName := bkt.Package.Name
	if bkt.Package.Module != "" {
		// Add modular namespace
		// e.g. nodejs:12::npm
		pkgName = fmt.Sprintf("%s::%s", bkt.Package.Module, pkgName)
	}

	if err := vs.dbc.PutAdvisoryDetail(tx, vulnID, pkgName, []string{rootBucket}, adv); err != nil {
		return xerrors.Errorf("failed to save Red Hat CSAF advisory: %w", err)
	}

	if err := vs.dbc.PutVulnerabilityID(tx, vulnID); err != nil {
		return xerrors.Errorf("failed to put vulnerability ID: %w", err)
	}

	return nil
}

// Get retrieves advisories for a package.
// TODO: The Get implementation is the same as redhat-oval since both use the same DB structure.
// When redhat-oval is removed in the future, move the Get implementation here.
func (vs VulnSrc) Get(pkgName string, repositories, nvrs []string) ([]types.Advisory, error) {
	return redhatoval.NewVulnSrc().Get(pkgName, repositories, nvrs)
}
