package vulnsrc

import (
	"log"
	"path/filepath"
	"sort"
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

type TargetWithPriority struct {
	Target   string
	Priority int
}

var (
	// UpdateList has list of update distributions
	UpdateList []string
	updateMap  = map[TargetWithPriority]VulnSrc{
		{Target: vulnerability.Nvd, Priority: 0}:                    nvd.NewVulnSrc(),
		{Target: vulnerability.Alpine, Priority: 1}:                 alpine.NewVulnSrc(),
		{Target: vulnerability.RedHat, Priority: 2}:                 redhat.NewVulnSrc(),
		{Target: vulnerability.RedHatOVAL, Priority: 3}:             redhatoval.NewVulnSrc(),
		{Target: vulnerability.DebianOVAL, Priority: 4}:             debianoval.NewVulnSrc(),
		{Target: vulnerability.Debian, Priority: 5}:                 debian.NewVulnSrc(),
		{Target: vulnerability.Ubuntu, Priority: 6}:                 ubuntu.NewVulnSrc(),
		{Target: vulnerability.Amazon, Priority: 7}:                 amazon.NewVulnSrc(),
		{Target: vulnerability.OracleOVAL, Priority: 8}:             oracleoval.NewVulnSrc(),
		{Target: vulnerability.SuseCVRF, Priority: 9}:               susecvrf.NewVulnSrc(susecvrf.SUSEEnterpriseLinux),
		{Target: vulnerability.OpenSuseCVRF, Priority: 10}:          susecvrf.NewVulnSrc(susecvrf.OpenSUSE),
		{Target: vulnerability.Photon, Priority: 11}:                photon.NewVulnSrc(),
		{Target: vulnerability.RubySec, Priority: 12}:               bundler.NewVulnSrc(),
		{Target: vulnerability.PhpSecurityAdvisories, Priority: 13}: composer.NewVulnSrc(),
		{Target: vulnerability.NodejsSecurityWg, Priority: 14}:      node.NewVulnSrc(),
		{Target: vulnerability.PythonSafetyDB, Priority: 15}:        python.NewVulnSrc(),
		{Target: vulnerability.RustSec, Priority: 16}:               cargo.NewVulnSrc(),
		{Target: vulnerability.GHSAComposer, Priority: 17}:          ghsa.NewVulnSrc(ghsa.Composer),
		{Target: vulnerability.GHSAMaven, Priority: 18}:             ghsa.NewVulnSrc(ghsa.Maven),
		{Target: vulnerability.GHSANpm, Priority: 19}:               ghsa.NewVulnSrc(ghsa.Npm),
		{Target: vulnerability.GHSANuget, Priority: 20}:             ghsa.NewVulnSrc(ghsa.Nuget),
		{Target: vulnerability.GHSAPip, Priority: 21}:               ghsa.NewVulnSrc(ghsa.Pip),
		{Target: vulnerability.GHSARubygems, Priority: 22}:          ghsa.NewVulnSrc(ghsa.Rubygems),
	}
)

func init() {
	UpdateList = make([]string, 0, len(updateMap))
	sortedKeys := make([]TargetWithPriority, 0, len(updateMap))
	for distribution := range updateMap {
		sortedKeys = append(sortedKeys, distribution)
	}
	sort.Slice(sortedKeys, func(i, j int) bool {
		return sortedKeys[i].Priority < sortedKeys[j].Priority
	})
	for _, distribution := range sortedKeys {
		UpdateList = append(UpdateList, distribution.Target)
	}
}

type Operation interface {
	SetMetadata(metadata db.Metadata) (err error)
	StoreMetadata(metadata db.Metadata, dir string) (err error)
}

type Updater struct {
	dbc            Operation
	updateMap      map[TargetWithPriority]VulnSrc
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

	sortedKeys := make([]TargetWithPriority, 0, len(u.updateMap))
	for distribution := range u.updateMap {
		sortedKeys = append(sortedKeys, distribution)
	}
	sort.Slice(sortedKeys, func(i, j int) bool {
		return sortedKeys[i].Priority < sortedKeys[j].Priority
	})

	for _, t := range sortedKeys {
		var (
			found         bool
			missingTarget string
		)
		for _, distribution := range targets {
			missingTarget = distribution
			if t.Target == distribution {
				found = true
				vulnSrc := u.updateMap[t]
				log.Printf("Updating %s data...\n", distribution)
				if err := vulnSrc.Update(u.cacheDir); err != nil {
					return xerrors.Errorf("error in %s update: %w", distribution, err)
				}
				break
			}
		}
		if !found {
			return xerrors.Errorf("%s does not supported yet", missingTarget)
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
	vuln := getDetailFunc(cveID)
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
	vuln := getDetailFunc(cveID)
	lightVuln := types.Vulnerability{
		VendorSeverity: vuln.VendorSeverity,
	}

	// TODO: We have to keep this "severity" variable for the "severity" bucket until we deprecate
	// GetDetail converts types.Severity to string, so this line just reconverts it.
	severity, _ := types.NewSeverity(vuln.Severity)

	// TODO: We have to keep the "severity" bucket until we deprecate
	// overwrite unknown severity with correct severity
	if err := o.dbOp.PutSeverity(tx, cveID, severity); err != nil {
		return xerrors.Errorf("failed to put severity: %w", err)
	}

	if err := o.dbOp.PutVulnerability(tx, cveID, lightVuln); err != nil {
		return xerrors.Errorf("failed to put vulnerability: %w", err)
	}
	return nil
}
