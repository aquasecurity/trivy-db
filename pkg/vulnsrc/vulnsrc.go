package vulnsrc

import (
	"log"
	"path/filepath"
	"time"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/alpine"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/amazon"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bundler"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/cargo"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/composer"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/debian"
	debianoval "github.com/aquasecurity/trivy-db/pkg/vulnsrc/debian-oval"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/ghsa"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/nvd"
	oracleoval "github.com/aquasecurity/trivy-db/pkg/vulnsrc/oracle-oval"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/photon"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/python"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/redhat"
	redhatoval "github.com/aquasecurity/trivy-db/pkg/vulnsrc/redhat-oval"
	susecvrf "github.com/aquasecurity/trivy-db/pkg/vulnsrc/suse-cvrf"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/ubuntu"

	"k8s.io/utils/clock"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/node"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"

	bolt "go.etcd.io/bbolt"

	"golang.org/x/xerrors"
)

type VulnSrc interface {
	Update(dir string) (err error)
}

var (
	// UpdateList has list of update distributions
	UpdateList []string
	updateMap  = map[string]VulnSrc{
		vulnerability.Nvd:                   nvd.NewVulnSrc(),
		vulnerability.Alpine:                alpine.NewVulnSrc(),
		vulnerability.RedHat:                redhat.NewVulnSrc(),
		vulnerability.RedHatOVAL:            redhatoval.NewVulnSrc(),
		vulnerability.Debian:                debian.NewVulnSrc(),
		vulnerability.DebianOVAL:            debianoval.NewVulnSrc(),
		vulnerability.Ubuntu:                ubuntu.NewVulnSrc(),
		vulnerability.Amazon:                amazon.NewVulnSrc(),
		vulnerability.OracleOVAL:            oracleoval.NewVulnSrc(),
		vulnerability.SuseCVRF:              susecvrf.NewVulnSrc(susecvrf.SUSEEnterpriseLinux),
		vulnerability.OpenSuseCVRF:          susecvrf.NewVulnSrc(susecvrf.OpenSUSE),
		vulnerability.Photon:                photon.NewVulnSrc(),
		vulnerability.RubySec:               bundler.NewVulnSrc(),
		vulnerability.PhpSecurityAdvisories: composer.NewVulnSrc(),
		vulnerability.NodejsSecurityWg:      node.NewVulnSrc(),
		vulnerability.PythonSafetyDB:        python.NewVulnSrc(),
		vulnerability.RustSec:               cargo.NewVulnSrc(),
		vulnerability.GHSAComposer:          ghsa.NewVulnSrc(ghsa.Composer),
		vulnerability.GHSAMaven:             ghsa.NewVulnSrc(ghsa.Maven),
		vulnerability.GHSANpm:               ghsa.NewVulnSrc(ghsa.Npm),
		vulnerability.GHSANuget:             ghsa.NewVulnSrc(ghsa.Nuget),
		vulnerability.GHSAPip:               ghsa.NewVulnSrc(ghsa.Pip),
		vulnerability.GHSARubygems:          ghsa.NewVulnSrc(ghsa.Rubygems),
	}
)

func init() {
	UpdateList = make([]string, 0, len(updateMap))
	for distribution := range updateMap {
		UpdateList = append(UpdateList, distribution)
	}
}

type Operation interface {
	SetMetadata(metadata db.Metadata) (err error)
	StoreMetadata(metadata db.Metadata, dir string) (err error)
}

type Updater struct {
	dbc            Operation
	updateMap      map[string]VulnSrc
	cacheDir       string
	dbType         db.Type
	updateInterval time.Duration
	clock          clock.Clock
	optimizer      Optimizer
}

func NewUpdater(cacheDir string, light bool, interval time.Duration) Updater {
	var optimizer Optimizer
	dbType := db.TypeFull
	dbConfig := db.Config{}
	optimizer = fullOptimizer{dbc: dbConfig}

	if light {
		dbType = db.TypeLight
		optimizer = lightOptimizer{dbOp: dbConfig}
	}

	return Updater{
		dbc:            dbConfig,
		updateMap:      updateMap,
		cacheDir:       cacheDir,
		dbType:         dbType,
		updateInterval: interval,
		clock:          clock.RealClock{},
		optimizer:      optimizer,
	}
}

func (u Updater) Update(targets []string) error {
	log.Println("Updating vulnerability database...")

	for _, distribution := range targets {
		vulnSrc, ok := u.updateMap[distribution]
		if !ok {
			return xerrors.Errorf("%s does not supported yet", distribution)
		}
		log.Printf("Updating %s data...\n", distribution)

		if err := vulnSrc.Update(u.cacheDir); err != nil {
			return xerrors.Errorf("error in %s update: %w", distribution, err)
		}
	}

	md := db.Metadata{
		Version:    db.SchemaVersion,
		Type:       u.dbType,
		NextUpdate: u.clock.Now().UTC().Add(u.updateInterval),
		UpdatedAt:  u.clock.Now().UTC(),
	}

	err := u.dbc.SetMetadata(md)
	if err != nil {
		return xerrors.Errorf("failed to save metadata: %w", err)
	}

	err = u.dbc.StoreMetadata(md, filepath.Join(u.cacheDir, "db"))
	if err != nil {
		return xerrors.Errorf("failed to store metadata: %w", err)
	}

	return u.optimizer.Optimize()
}

type Optimizer interface {
	Optimize() (err error)
}

type fullOptimizer struct {
	dbc db.Operation
}

func (o fullOptimizer) Optimize() error {
	err := o.dbc.ForEachSeverity(func(tx *bolt.Tx, cveID string, _ types.Severity) error {
		return o.fullOptimize(tx, cveID)
	})
	if err != nil {
		return xerrors.Errorf("failed to iterate severity: %w", err)
	}

	if err := o.dbc.DeleteSeverityBucket(); err != nil {
		return xerrors.Errorf("failed to delete severity bucket: %w", err)
	}

	if err := o.dbc.DeleteVulnerabilityDetailBucket(); err != nil {
		return xerrors.Errorf("failed to delete vulnerability detail bucket: %w", err)
	}

	return nil

}

// TODO: Until we can dependency inject, we need to monkey patch sadly
var (
	getDetailFunc = vulnerability.GetDetail
)

func (o fullOptimizer) fullOptimize(tx *bolt.Tx, cveID string) error {
	severity, vs, vc, vv, title, description, references := getDetailFunc(cveID)
	vuln := types.Vulnerability{
		Title:          title,
		Description:    description,
		Severity:       severity.String(), // TODO: We have to keep this key until we deprecate
		References:     references,
		VendorSeverity: vs,
		VendorVectors:  vv, // TODO: We have to keep this for backwards compatibility.
		CVSS:           vc,
	}

	if err := o.dbc.PutVulnerability(tx, cveID, vuln); err != nil {
		return xerrors.Errorf("failed to put vulnerability: %w", err)
	}
	return nil
}

type lightOptimizer struct {
	dbOp db.Operation
}

func (o lightOptimizer) Optimize() error {
	err := o.dbOp.ForEachSeverity(func(tx *bolt.Tx, cveID string, _ types.Severity) error {
		return o.lightOptimize(cveID, tx)
	})
	if err != nil {
		return xerrors.Errorf("failed to iterate severity: %w", err)
	}

	if err = o.dbOp.DeleteVulnerabilityDetailBucket(); err != nil {
		return xerrors.Errorf("failed to delete vulnerability detail bucket: %w", err)
	}
	return nil
}

func (o lightOptimizer) lightOptimize(cveID string, tx *bolt.Tx) error {
	// get correct severity
	severity, vendorSeverity, _, _, _, _, _ := getDetailFunc(cveID)
	vuln := types.Vulnerability{
		VendorSeverity: vendorSeverity,
	}

	// TODO: We have to keep this bucket until we deprecate
	// overwrite unknown severity with correct severity
	if err := o.dbOp.PutSeverity(tx, cveID, severity); err != nil {
		return xerrors.Errorf("failed to put severity: %w", err)
	}

	if err := o.dbOp.PutVulnerability(tx, cveID, vuln); err != nil {
		return xerrors.Errorf("failed to put vulnerability: %w", err)
	}
	return nil
}
