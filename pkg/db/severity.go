package db

import (
	"github.com/aquasecurity/trivy-db/pkg/types"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
)

const (
	severityBucket = "severity"
)

func (dbc Config) PutSeverity(tx *bolt.Tx, cveID string, severity types.Severity) error {
	bkt, err := tx.CreateBucketIfNotExists([]byte(severityBucket))
	if err != nil {
		return xerrors.Errorf("unable to create '%s' bucket: %w", severityBucket, err)
	}

	if err = bkt.Put([]byte(cveID), []byte(severity.String())); err != nil {
		return xerrors.Errorf("severity put error: %w", err)
	}
	return nil
}

func (dbc Config) GetSeverity(cveID string) (severity types.Severity, err error) {
	err = db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(severityBucket))
		value := bucket.Get([]byte(cveID))
		severity, err = types.NewSeverity(string(value))
		if err != nil {
			return xerrors.Errorf("invalid severity: %w", err)
		}
		return nil
	})
	if err != nil {
		return types.SeverityUnknown, xerrors.Errorf("failed to get the severity: %w", err)
	}
	return severity, nil
}

func (dbc Config) ForEachSeverity(f func(tx *bolt.Tx, cveID string, severity types.Severity) error) error {
	err := db.Batch(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte(severityBucket))
		if err != nil {
			return xerrors.Errorf("failed to create a bucket: %w", err)
		}
		err = bucket.ForEach(func(cveID, v []byte) error {
			severity, err := types.NewSeverity(string(v))
			if err != nil {
				return xerrors.Errorf("unknown severity: %w", err)
			}
			if err = f(tx, string(cveID), severity); err != nil {
				return xerrors.Errorf("something wrong: %w", err)
			}
			return nil
		})
		if err != nil {
			return xerrors.Errorf("severity for each error: %w", err)
		}
		return nil
	})
	return err
}

func (dbc Config) DeleteSeverityBucket() error {
	return dbc.deleteBucket(severityBucket)
}
