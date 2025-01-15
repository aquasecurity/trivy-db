package redhatcsaf

import (
	"log"

	"github.com/samber/oops"
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
	eb := oops.In("redhat_csaf_vex")

	log.Print("Parsing CSAF VEX...")
	if err := vs.parser.Parse(dir); err != nil {
		return eb.Wrapf(err, "failed to parse CSAF VEX")
	}
	log.Print("Parsed CSAF VEX")

	log.Print("Inserting CSAF VEX...")
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
		if err := vs.putAdvisory(bkt, advisory); err != nil {
			return eb.Wrapf(err, "failed to put advisory")
		}
		bar.Increment()
	}
	bar.Finish()

	return nil
}

func (vs VulnSrc) putAdvisory(bkt Bucket, adv Advisory) error {
	return nil
	//err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
	//	if err := vs.dbc.PutDataSource(tx, rootBucket, source); err != nil {
	//		return xerrors.Errorf("failed to put data source: %w", err)
	//	}
	//
	//	vulnID := string(bkt.VulnerabilityID)
	//	pkgName := bkt.Package.Name // TODO: support modules
	//	if err := vs.dbc.PutAdvisoryDetail(tx, vulnID, pkgName, []string{rootBucket}, adv); err != nil {
	//		return xerrors.Errorf("failed to save Red Hat CSAF advisory: %w", err)
	//	}
	//
	//	if err := vs.dbc.PutVulnerabilityID(tx, vulnID); err != nil {
	//		return xerrors.Errorf("failed to put vulnerability ID: %w", err)
	//	}
	//
	//	return nil
	//})
	//
	//if err != nil {
	//	return xerrors.Errorf("batch update error: %w", err)
	//}
	//
	//return nil
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
