package db

import (
	bolt "github.com/etcd-io/bbolt"
	"golang.org/x/xerrors"
)

func (dbc Config) PutAdvisory(tx *bolt.Tx, source, pkgName, cveID string, advisory interface{}) error {
	root, err := tx.CreateBucketIfNotExists([]byte(source))
	if err != nil {
		return xerrors.Errorf("failed to create a bucket: %w", err)
	}
	return dbc.put(root, pkgName, cveID, advisory)
}

func (dbc Config) ForEachAdvisory(source, pkgName string) (value map[string][]byte, err error) {
	return dbc.forEach(source, pkgName)
}
