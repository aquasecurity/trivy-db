package db

import (
	"encoding/json"

	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/types"
)

const (
	dataSourceBucket = "data-source"
)

func (dbc Config) PutDataSource(tx *bolt.Tx, bktName string, source types.DataSource) error {
	eb := oops.With("root_bucket", dataSourceBucket).With("bucket_name", bktName)
	bucket, err := tx.CreateBucketIfNotExists([]byte(dataSourceBucket))
	if err != nil {
		return eb.Wrapf(err, "failed to create bucket")
	}
	b, err := json.Marshal(source)
	if err != nil {
		return eb.Wrapf(err, "json marshal error")
	}

	return bucket.Put([]byte(bktName), b)
}

func (dbc Config) getDataSource(tx *bolt.Tx, bktName string) (types.DataSource, error) {
	eb := oops.With("root_bucket", dataSourceBucket).With("bucket_name", bktName)
	bucket := tx.Bucket([]byte(dataSourceBucket))
	if bucket == nil {
		return types.DataSource{}, nil
	}

	b := bucket.Get([]byte(bktName))
	if b == nil {
		return types.DataSource{}, nil
	}

	var source types.DataSource
	if err := json.Unmarshal(b, &source); err != nil {
		return types.DataSource{}, eb.Wrapf(err, "json unmarshal error")
	}

	return source, nil
}
