package db

import (
	"encoding/json"
	"github.com/aquasecurity/trivy-db/pkg/types"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
)

const k8sRootBucket = "k8s"
const DbBucket = "db"
const DataSourceBucket = "data-source"

func (dbc Config) PutK8sDataSource(tx *bolt.Tx, bktName string, source types.DataSource) (err error) {
	rootBucket, err := tx.CreateBucketIfNotExists([]byte(k8sRootBucket))
	if err != nil {
		return xerrors.Errorf("failed to create %s bucket: %w", k8sRootBucket, err)
	}
	dataSource, err := rootBucket.CreateBucketIfNotExists([]byte(DataSourceBucket))
	if err != nil {
		return xerrors.Errorf("failed to create %s bucket: %w", DataSourceBucket, err)
	}
	value, err := json.Marshal(source)
	if err != nil {
		return xerrors.Errorf("JSON marshal error: %w", err)
	}

	return dataSource.Put([]byte(bktName), value)
}

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
		dbBucket := tx.Bucket([]byte(k8sRootBucket)).Bucket([]byte(DbBucket))
		value := dbBucket.Get([]byte(key))
		if value == nil {
			return xerrors.Errorf("no k8s Data details for %s", key)
		}
		return json.Unmarshal(value, &k8sData)
	})
}
