package vulnsrc

import (
	"log"
	"time"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/alpine"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/amazon"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/debian"
	debianoval "github.com/aquasecurity/trivy-db/pkg/vulnsrc/debian-oval"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/nvd"
	oracleoval "github.com/aquasecurity/trivy-db/pkg/vulnsrc/oracle-oval"
	redhatoval "github.com/aquasecurity/trivy-db/pkg/vulnsrc/redhat-oval"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/ubuntu"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bundler"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/cargo"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/composer"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/node"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/python"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/redhat"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"

	bolt "github.com/etcd-io/bbolt"

	"golang.org/x/xerrors"
)

type Updater interface {
	Update(string) error
}

var (
	// UpdateList has list of update distributions
	UpdateList []string
	updateMap  = map[string]Updater{
		vulnerability.Nvd:                   nvd.NewVulnSrc(),
		vulnerability.Alpine:                alpine.NewVulnSrc(),
		vulnerability.RedHat:                redhat.NewVulnSrc(),
		vulnerability.RedHatOVAL:            redhatoval.NewVulnSrc(),
		vulnerability.Debian:                debian.NewVulnSrc(),
		vulnerability.DebianOVAL:            debianoval.NewVulnSrc(),
		vulnerability.Ubuntu:                ubuntu.NewVulnSrc(),
		vulnerability.Amazon:                amazon.NewVulnSrc(),
		vulnerability.RubySec:               bundler.NewVulnSrc(),
		vulnerability.PhpSecurityAdvisories: composer.NewVulnSrc(),
		vulnerability.NodejsSecurityWg:      node.NewVulnSrc(),
		vulnerability.PythonSafetyDB:        python.NewVulnSrc(),
		vulnerability.RustSec:               cargo.NewVulnSrc(),
		vulnerability.OracleOVAL:            oracleoval.NewVulnSrc(),
	}
)

func init() {
	UpdateList = make([]string, 0, len(updateMap))
	for distribution := range updateMap {
		UpdateList = append(UpdateList, distribution)
	}
}

func Update(targets []string, cacheDir string, light bool, updateInterval time.Duration) error {
	log.Println("Updating vulnerability database...")

	for _, distribution := range targets {
		vulnSrc, ok := updateMap[distribution]
		if !ok {
			return xerrors.Errorf("%s does not supported yet", distribution)
		}
		log.Printf("Updating %s data...\n", distribution)

		if err := vulnSrc.Update(cacheDir); err != nil {
			return xerrors.Errorf("error in %s update: %w", distribution, err)
		}
	}

	dbc := db.Config{}
	dbType := db.TypeFull
	if light {
		dbType = db.TypeLight
	}

	err := dbc.SetMetadata(db.Metadata{
		Version:    db.SchemaVersion,
		Type:       dbType,
		NextUpdate: time.Now().UTC().Add(updateInterval),
		UpdatedAt:  time.Now().UTC(),
	})
	if err != nil {
		return xerrors.Errorf("failed to save metadata: %w", err)
	}

	if light {
		return optimizeLightDB(dbc)
	}
	return optimizeFullDB(dbc)
}

func optimizeFullDB(dbc db.Config) error {
	err := dbc.ForEachSeverity(func(tx *bolt.Tx, cveID string, _ types.Severity) error {
		severity, title, description, references := vulnerability.GetDetail(cveID)
		vuln := types.Vulnerability{
			Title:       title,
			Description: description,
			Severity:    severity.String(),
			References:  references,
		}
		if err := dbc.PutVulnerability(tx, cveID, vuln); err != nil {
			return xerrors.Errorf("failed to put vulnerability: %w", err)
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("failed to iterate vulnerability: %w", err)
	}

	if err := dbc.DeleteSeverityBucket(); err != nil {
		return xerrors.Errorf("failed to delete severity bucket: %w", err)
	}

	if err := dbc.DeleteVulnerabilityDetailBucket(); err != nil {
		return xerrors.Errorf("failed to delete vulnerability detail bucket: %w", err)
	}

	return nil

}

func optimizeLightDB(dbc db.Config) error {
	err := dbc.ForEachSeverity(func(tx *bolt.Tx, cveID string, _ types.Severity) error {
		// get correct severity
		sev, _, _, _ := vulnerability.GetDetail(cveID)

		// overwrite unknown severity with correct severity
		if err := dbc.PutSeverity(tx, cveID, sev); err != nil {
			return xerrors.Errorf("failed to put severity: %w", err)
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("failed to iterate severity: %w", err)
	}

	if err = dbc.DeleteVulnerabilityDetailBucket(); err != nil {
		return xerrors.Errorf("failed to delete vulnerability detail bucket: %w", err)
	}
	return nil
}
