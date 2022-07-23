package db

import (
	"encoding/json"
	"github.com/aquasecurity/trivy-db/pkg/types"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
)

const k8sBucket = "k8s"

func (dbc Config) AddK8sOutdatedAPI(tx *bolt.Tx, key string, apis interface{}) (err error) {
	if err := dbc.put(tx, []string{k8sBucket}, key, apis); err != nil {
		return xerrors.Errorf("failed to put k8s api data: %w", err)
	}
	return nil
}

func (dbc Config) GetOutdatedAPI(key string) (*types.OutDatedAPIData, error) {
	var outdatedapi types.OutDatedAPIData
	err := db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(k8sBucket))
		value := bucket.Get([]byte(key))
		if value == nil {
			return xerrors.Errorf("no outdated-api details for %s", key)
		}
		if err := json.Unmarshal(value, &outdatedapi); err != nil {
			return xerrors.Errorf("failed to unmarshal JSON: %w", err)
		}
		return nil
	})
	if err != nil {
		return &types.OutDatedAPIData{}, xerrors.Errorf("failed to get the outdated-api %q: %w", key, err)
	}
	return &outdatedapi, nil
}
