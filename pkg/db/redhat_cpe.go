package db

import (
	"encoding/json"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
)

const (
	redhatCPEBucket = "Red Hat CPE"
)

func (dbc Config) PutRedHatCPEs(tx *bolt.Tx, repository string, cpes []string) error {
	bucket, err := tx.CreateBucketIfNotExists([]byte(redhatCPEBucket))
	if err != nil {
		return xerrors.Errorf("failed to create a bucket (%s): %w", redhatCPEBucket, err)
	}

	b, err := json.MarshalIndent(cpes, "", "  ")
	if err != nil {
		return xerrors.Errorf("JSON parse error: %w", err)
	}
	if err = bucket.Put([]byte(repository), b); err != nil {
		return xerrors.Errorf("failed to put a mapping: %w", err)
	}

	return nil
}

func (dbc Config) GetRedHatCPEs(repository string) ([]string, error) {
	var cpes []string
	err := db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(redhatCPEBucket))
		if bucket == nil {
			return nil
		}

		b := bucket.Get([]byte(repository))
		if len(b) == 0 {
			return nil
		}
		if err := json.Unmarshal(b, &cpes); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return cpes, nil
}
