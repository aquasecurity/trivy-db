package vulndb

import (
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
)

type fullDB struct {
	*Core
}

func (f fullDB) Build(targets []string) error {
	// Insert all security advisories
	if err := f.Insert(db.TypeFull, targets); err != nil {
		return xerrors.Errorf("insert error: %w", err)
	}

	// Remove unnecessary details
	if err := f.optimize(); err != nil {
		return xerrors.Errorf("optimize error: %w", err)
	}

	// Remove unnecessary buckets
	if err := f.cleanup(); err != nil {
		return xerrors.Errorf("cleanup error: %w", err)
	}

	return nil
}

func (f fullDB) optimize() error {
	err := f.dbc.ForEachSeverity(func(tx *bolt.Tx, cveID string, _ types.Severity) error {
		details := f.vulnClient.GetDetails(cveID)
		if f.vulnClient.IsRejected(details) {
			return nil
		}

		if err := f.vulnClient.SaveAdvisoryDetails(tx, cveID); err != nil {
			return xerrors.Errorf("failed to save advisories: %w", err)
		}

		vuln := f.vulnClient.Normalize(details)
		if err := f.dbc.PutVulnerability(tx, cveID, vuln); err != nil {
			return xerrors.Errorf("failed to put vulnerability: %w", err)
		}

		return nil
	})

	if err != nil {
		return xerrors.Errorf("failed to iterate severity: %w", err)
	}

	return nil
}

func (f fullDB) cleanup() error {
	if err := f.dbc.DeleteSeverityBucket(); err != nil {
		return xerrors.Errorf("failed to delete severity bucket: %w", err)
	}

	if err := f.dbc.DeleteVulnerabilityDetailBucket(); err != nil {
		return xerrors.Errorf("failed to delete vulnerability detail bucket: %w", err)
	}

	if err := f.dbc.DeleteAdvisoryDetailBucket(); err != nil {
		return xerrors.Errorf("failed to delete advisory detail bucket: %w", err)
	}

	return nil
}
