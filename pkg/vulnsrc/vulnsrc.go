package vulnsrc

import (
	"log"
	"time"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/alpine"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/amazon"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bundler"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/cargo"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/composer"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/debian"
	debianoval "github.com/aquasecurity/trivy-db/pkg/vulnsrc/debian-oval"
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

	bolt "github.com/etcd-io/bbolt"

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
	dbConfig := db.Config{}
	dbType := db.TypeFull
	optimizer = fullOptimizer{dbc: dbConfig}

	if light {
		dbType = db.TypeLight
		optimizer = lightOptimizer{dbc: dbConfig}
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

	err := u.dbc.SetMetadata(db.Metadata{
		Version:    db.SchemaVersion,
		Type:       u.dbType,
		NextUpdate: u.clock.Now().UTC().Add(u.updateInterval),
		UpdatedAt:  u.clock.Now().UTC(),
	})
	if err != nil {
		return xerrors.Errorf("failed to save metadata: %w", err)
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
		severity, vs, title, description, references := vulnerability.GetDetail(cveID)
		vuln := types.Vulnerability{
			Title:          title,
			Description:    description,
			Severity:       severity.String(),
			VendorSeverity: vs,
			References:     references,
		}
		if err := o.dbc.PutVulnerability(tx, cveID, vuln); err != nil {
			return xerrors.Errorf("failed to put vulnerability: %w", err)
		}
		return nil
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

type lightOptimizer struct {
	dbc db.Operation
}

func (o lightOptimizer) Optimize() error {
	err := o.dbc.ForEachSeverity(func(tx *bolt.Tx, cveID string, _ types.Severity) error {
		// get correct severity
		sev, _, _, _, _ := vulnerability.GetDetail(cveID)

		// overwrite unknown severity with correct severity
		if err := o.dbc.PutSeverity(tx, cveID, sev); err != nil {
			return xerrors.Errorf("failed to put severity: %w", err)
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("failed to iterate severity: %w", err)
	}

	if err = o.dbc.DeleteVulnerabilityDetailBucket(); err != nil {
		return xerrors.Errorf("failed to delete vulnerability detail bucket: %w", err)
	}
	return nil
}
