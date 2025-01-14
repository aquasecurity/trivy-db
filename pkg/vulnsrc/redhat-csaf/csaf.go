package redhatcsaf

import (
	"fmt"
	"log"
	"path/filepath"

	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
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

	log.Println("Parsing CSAF VEX...")
	vulnListDir := filepath.Join(dir, vulnListDir)
	if err := vs.parser.Parse(vulnListDir); err != nil {
		return eb.Wrapf(err, "failed to parse CSAF VEX")
	}
	log.Println("Parsed CSAF VEX")

	cpeList := vs.parser.CPEList()

	log.Println("Inserting mappings...")
	if err := vs.putMappings(tx, cpeList); err != nil {
		return eb.Wrapf(err, "failed to put mappings")
	}

	log.Println("Inserting CSAF VEX...")
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

func (vs VulnSrc) putMappings(tx *bolt.Tx, cpeList CPEList) error {
	// TODO(debug): delete
	vs.dbc.PutVulnerabilityDetail(tx, "aaa", source.ID, types.VulnerabilityDetail{})

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

func (vs VulnSrc) putAdvisory(tx *bolt.Tx, bkt Bucket, adv Advisory, cpeList CPEList) error {
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

//func (vs VulnSrc) Get(pkgName string, repositories, nvrs []string) ([]types.Advisory, error) {
//	var advisories []types.Advisory
//
//	err := vs.dbc.View(func(tx *bolt.Tx) error {
//		bucket := tx.Bucket([]byte(rootBucket))
//		if bucket == nil {
//			return nil
//		}
//
//		return bucket.ForEach(func(k, v []byte) error {
//			var advisory Advisory
//			if err := json.Unmarshal(v, &advisory); err != nil {
//				return xerrors.Errorf("failed to unmarshal advisory JSON: %w", err)
//			}
//
//			if advisory.PkgName == pkgName {
//				advisories = append(advisories, types.Advisory{
//					VulnerabilityID: advisory.VulnerabilityID,
//					FixedVersion:    advisory.FixedVersion,
//					Severity:        advisory.Severity,
//				})
//			}
//
//			return nil
//		})
//	})
//
//	if err != nil {
//		return nil, xerrors.Errorf("failed to get advisories: %w", err)
//	}
//
//	return advisories, nil
//}

// Helper function to use ProductIdentificationHelpers
//func (vs VulnSrc) getProductPURLs(adv csaf.Advisory, productID csaf.ProductID) []string {
//	helpers := adv.ProductTree.CollectProductIdentificationHelpers(productID)
//	var purls []string
//	for _, helper := range helpers {
//		if helper.PURL != nil {
//			purls = append(purls, string(*helper.PURL))
//		}
//	}
//	return purls
//}
