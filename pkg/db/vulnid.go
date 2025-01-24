package db

import (
	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"
)

const (
	vulnerabilityIDBucket = "vulnerability-id"
)

func (dbc Config) PutVulnerabilityID(tx *bolt.Tx, vulnID string) error {
	bucket, err := tx.CreateBucketIfNotExists([]byte(vulnerabilityIDBucket))
	if err != nil {
		return oops.With("bucket_name", vulnerabilityIDBucket).With("vuln_id", vulnID).Wrapf(err, "failed to create bucket")
	}
	return bucket.Put([]byte(vulnID), []byte("{}"))
}

func (dbc Config) ForEachVulnerabilityID(f func(tx *bolt.Tx, vulnID string) error) error {
	eb := oops.With("bucket_name", vulnerabilityIDBucket)
	err := db.Batch(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(vulnerabilityIDBucket))
		if bucket == nil {
			return eb.Errorf("no such bucket")
		}
		err := bucket.ForEach(func(vulnID, _ []byte) error {
			if err := f(tx, string(vulnID)); err != nil {
				return eb.With("vuln_id", vulnID).Wrapf(err, "something wrong")
			}
			return nil
		})
		if err != nil {
			return eb.Wrapf(err, "for each error")
		}
		return nil
	})
	return err
}

func (dbc Config) DeleteVulnerabilityIDBucket() error {
	return dbc.deleteBucket(vulnerabilityIDBucket)
}
