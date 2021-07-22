package db

import (
	"encoding/json"

	bolt "go.etcd.io/bbolt"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/types"
)

const (
	advisoryDetailBucket = "advisory-detail"
)

func (dbc Config) PutAdvisoryDetail(tx *bolt.Tx, vulnerabilityID string, source string, pkgName string,
	advisory interface{}) (err error) {
	root, err := tx.CreateBucketIfNotExists([]byte(advisoryDetailBucket))
	if err != nil {
		return err
	}
	nested, err := root.CreateBucketIfNotExists([]byte(vulnerabilityID))
	if err != nil {
		return err
	}
	return dbc.put(nested, source, pkgName, advisory)
}

func (dbc Config) GetAdvisoryDetails(cveID string) ([]types.AdvisoryDetail, error) {
	var advisories []types.AdvisoryDetail
	err := db.View(func(tx *bolt.Tx) error {
		root := tx.Bucket([]byte(advisoryDetailBucket))
		if root == nil {
			return nil
		}
		cveBucket := root.Bucket([]byte(cveID))
		if cveBucket == nil {
			return nil
		}
		err := cveBucket.ForEach(func(platform, v []byte) error {
			packageBucket := cveBucket.Bucket(platform)
			if packageBucket == nil {
				return nil
			}
			err := packageBucket.ForEach(func(packageName, v []byte) error {
				detail := map[string]interface{}{}
				if err := json.Unmarshal(v, &detail); err != nil {
					return xerrors.Errorf("failed to unmarshall advisory_detail: %w", err)
				}
				advisories = append(advisories, types.AdvisoryDetail{
					PlatformName: string(platform),
					PackageName:  string(packageName),
					AdvisoryItem: detail,
				})
				return nil
			})
			return err
		})
		if err != nil {
			return xerrors.Errorf("error in db foreach: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("failed to get all key/value in the specified bucket: %w", err)
	}
	return advisories, nil
}

func (dbc Config) DeleteAdvisoryDetailBucket() error {
	return dbc.deleteBucket(advisoryDetailBucket)
}

func (dbc Config) GetAdvisoryDetail(tx *bolt.Tx, cveID string, platformName string, pkgName string) (types.AdvisoryDetail, error) {
	advisory := types.AdvisoryDetail{}
	root := tx.Bucket([]byte(advisoryDetailBucket))
	if root == nil {
		return advisory, nil
	}
	cveBucket := root.Bucket([]byte(cveID))
	if cveBucket == nil {
		return advisory, nil
	}
	err := cveBucket.ForEach(func(platform, v []byte) error {
		packageBucket := cveBucket.Bucket(platform)
		if packageBucket == nil {
			return nil
		}
		err := packageBucket.ForEach(func(packageName, v []byte) error {
			var detail types.Advisory
			if err := json.Unmarshal(v, &detail); err != nil {
				return xerrors.Errorf("failed to unmarshall advisory_detail: %w", err)
			}
			if string(packageName) == pkgName && string(platform) == platformName {
				advisory = types.AdvisoryDetail{
					PlatformName: string(platform),
					PackageName:  string(packageName),
					AdvisoryItem: detail,
				}

				return nil
			}
			return nil
		})
		return err
	})
	if err != nil {
		return advisory, xerrors.Errorf("error in db foreach: %w", err)
	}
	return advisory, nil
}
