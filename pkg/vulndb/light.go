package vulndb

import (
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
)

type lightDB struct {
	*Core
}

func (l lightDB) Build(targets []string) error {
	// Insert all security advisories
	if err := l.Insert(db.TypeLight, targets); err != nil {
		return xerrors.Errorf("insert error: %w", err)
	}

	// Remove unnecessary details
	if err := l.optimize(); err != nil {
		return xerrors.Errorf("optimize error: %w", err)
	}

	// Remove unnecessary buckets
	if err := l.cleanup(); err != nil {
		return xerrors.Errorf("cleanup error: %w", err)
	}

	return nil
}

func (l lightDB) optimize() error {
	err := l.dbc.ForEachSeverity(func(tx *bolt.Tx, cveID string, _ types.Severity) error {
		// get correct severity
		details := l.vulnClient.GetDetails(cveID)
		if l.vulnClient.IsRejected(details) {
			return nil
		}

		if err := l.vulnClient.SaveAdvisoryDetails(tx, cveID); err != nil {
			return xerrors.Errorf("failed to save advisories: %w", err)
		}

		vuln := l.vulnClient.Normalize(details)
		lightVuln := types.Vulnerability{
			VendorSeverity: vuln.VendorSeverity,
		}

		// TODO: We have to keep this "severity" variable for the "severity" bucket until we deprecate
		// GetDetail converts types.Severity to string, so this line just reconverts it.
		severity, _ := types.NewSeverity(vuln.Severity)

		// TODO: We have to keep the "severity" bucket until we deprecate
		// overwrite unknown severity with correct severity
		if err := l.dbc.PutSeverity(tx, cveID, severity); err != nil {
			return xerrors.Errorf("failed to put severity: %w", err)
		}

		if err := l.dbc.PutVulnerability(tx, cveID, lightVuln); err != nil {
			return xerrors.Errorf("failed to put vulnerability: %w", err)
		}

		return nil
	})

	if err != nil {
		return xerrors.Errorf("failed to iterate severity: %w", err)
	}

	return nil
}

func (l lightDB) cleanup() error {
	if err := l.dbc.DeleteVulnerabilityDetailBucket(); err != nil {
		return xerrors.Errorf("failed to delete vulnerability detail bucket: %w", err)
	}

	if err := l.dbc.DeleteAdvisoryDetailBucket(); err != nil {
		return xerrors.Errorf("failed to delete advisory detail bucket: %w", err)
	}

	return nil
}
