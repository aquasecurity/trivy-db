package db

import (
	"encoding/json"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
)

const k8sRootBucket = "k8s"
const DbBucket = "db"

func (dbc Config) PutK8sDb(tx *bolt.Tx, key string, k8sData interface{}) (err error) {
	rootBucket, err := tx.CreateBucketIfNotExists([]byte(k8sRootBucket))
	if err != nil {
		return xerrors.Errorf("failed to create %s bucket: %w", k8sRootBucket, err)
	}
	dbBucket, err := rootBucket.CreateBucketIfNotExists([]byte(DbBucket))
	if err != nil {
		return xerrors.Errorf("failed to create %s bucket: %w", DbBucket, err)
	}
	value, err := json.Marshal(k8sData)
	if err != nil {
		return xerrors.Errorf("JSON marshal error: %w", err)
	}
	if err := dbBucket.Put([]byte(key), value); err != nil {
		return xerrors.Errorf("failed to put k8s api data: %w", err)
	}
	return nil
}

func (dbc Config) GetK8sDb(key string, k8sData interface{}) error {
	return db.View(func(tx *bolt.Tx) error {
		rootBucket := tx.Bucket([]byte(k8sRootBucket))
		if rootBucket == nil {
			return xerrors.Errorf("failed to fetch rootBucket %s, it does not exist", k8sRootBucket)
		}
		dbBucket := rootBucket.Bucket([]byte(DbBucket))
		if rootBucket == nil {
			return xerrors.Errorf("failed to fetch DbBucket %s, it does not exist under rootBucket %s", DbBucket, k8sRootBucket)
		}
		value := dbBucket.Get([]byte(key))
		if value == nil {
			return xerrors.Errorf("no k8s Data details for %s", key)
		}
		if err := json.Unmarshal(value, &k8sData); err != nil {
			return xerrors.Errorf("failed to unmarshal k8s api data for key %s: %w", key, err)
		}
		return nil
	})
}
