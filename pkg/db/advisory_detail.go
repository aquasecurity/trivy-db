package db

import (
	"encoding/json"

	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"
)

const (
	advisoryDetailBucket = "advisory-detail"
)

func (dbc Config) PutAdvisoryDetail(tx *bolt.Tx, vulnID, pkgName string, nestedBktNames []string, advisory interface{}) error {
	bktNames := append([]string{advisoryDetailBucket, vulnID}, nestedBktNames...)
	if err := dbc.put(tx, bktNames, pkgName, advisory); err != nil {
		return oops.With("vuln_id", vulnID).With("package_name", pkgName).Wrapf(err, "failed to put advisory detail")
	}
	return nil
}

// SaveAdvisoryDetails Extract advisories from 'advisory-detail' bucket and copy them in each
func (dbc Config) SaveAdvisoryDetails(tx *bolt.Tx, vulnID string) error {
	root := tx.Bucket([]byte(advisoryDetailBucket))
	if root == nil {
		return nil
	}

	cveBucket := root.Bucket([]byte(vulnID))
	if cveBucket == nil {
		return nil
	}

	if err := dbc.saveAdvisories(tx, cveBucket, []string{}, vulnID); err != nil {
		return oops.With("vuln_id", vulnID).Wrapf(err, "unable to save advisories")
	}

	return nil
}

// saveAdvisories walks all key-values under the 'advisory-detail' bucket and copy them in each vendor's bucket.
func (dbc Config) saveAdvisories(tx *bolt.Tx, bkt *bolt.Bucket, bktNames []string, vulnID string) error {
	if bkt == nil {
		return nil
	}
	eb := oops.With("bucket_names", bktNames).With("vuln_id", vulnID)

	err := bkt.ForEach(func(k, v []byte) error {
		// When the key is a bucket, it walks recursively.
		if v == nil {
			bkts := append(bktNames, string(k))
			if err := dbc.saveAdvisories(tx, bkt.Bucket(k), bkts, vulnID); err != nil {
				return eb.Wrapf(err, "unable to save advisories")
			}
		} else {
			detail := map[string]interface{}{}
			if err := json.Unmarshal(v, &detail); err != nil {
				return eb.Wrapf(err, "json unmarshal error")
			}

			// Put the advisory in vendor's bucket such as Debian and Ubuntu
			bkts := append(bktNames, string(k))
			if err := dbc.put(tx, bkts, vulnID, detail); err != nil {
				return eb.Wrapf(err, "database put error")
			}
		}

		return nil
	})
	if err != nil {
		return eb.Wrapf(err, "foreach error")
	}

	return nil
}

func (dbc Config) DeleteAdvisoryDetailBucket() error {
	return dbc.deleteBucket(advisoryDetailBucket)
}
