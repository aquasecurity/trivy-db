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

func (dbc Config) PutK8sOutdatedAPI(tx *bolt.Tx, key string, apis interface{}) (err error) {
	rootBucket, err := tx.CreateBucketIfNotExists([]byte(k8sRootBucket))
	if err != nil {
		return xerrors.Errorf("failed to create %s bucket: %w", k8sRootBucket, err)
	}
	dbBucket, err := rootBucket.CreateBucketIfNotExists([]byte(DbBucket))
	if err != nil {
		return xerrors.Errorf("failed to create %s bucket: %w", DbBucket, err)
	}
	value, err := json.Marshal(apis)
	if err != nil {
		return xerrors.Errorf("JSON marshal error: %w", err)
	}
	if err := dbBucket.Put([]byte(key), value); err != nil {
		return xerrors.Errorf("failed to put k8s api data: %w", err)
	}
	return nil
}

func (dbc Config) GetK8sOutdatedAPI(key string) (types.OutDatedAPIData, error) {
	var outdatedapi types.OutDatedAPIData
	err := db.View(func(tx *bolt.Tx) error {
		dbBucket := tx.Bucket([]byte(k8sRootBucket)).Bucket([]byte(DbBucket))
		value := dbBucket.Get([]byte(key))
		if value == nil {
			return xerrors.Errorf("no outdated-api details for %s", key)
		}
		if err := json.Unmarshal(value, &outdatedapi); err != nil {
			return xerrors.Errorf("failed to unmarshal JSON: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("failed to get the outdated-api %q: %w", key, err)
	}
	return outdatedapi, nil
}
