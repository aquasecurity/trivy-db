package db

import (
	"encoding/json"

	"github.com/aquasecurity/trivy-db/pkg/types"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
)

const (
	securityAdvisoryBucket = "security-advisory"
)

func (dbc Config) GetSecurityAdvisoryDetails(cveId string) (types.SecurityAdvisories, error) {
	SecurityAdvisories := types.SecurityAdvisories{}
	err := db.View(func(tx *bolt.Tx) error {
		root := tx.Bucket([]byte(securityAdvisoryBucket))
		if root == nil {
			return nil
		}
		cveBucket := root.Bucket([]byte(cveId))
		if cveBucket == nil {
			return nil
		}
		err := cveBucket.ForEach(func(platform, v []byte) error {
			securityAdvisory := make(map[string]types.SecurityAdvisory)
			advisoryBucket := cveBucket.Bucket(platform)
			if advisoryBucket == nil {
				return nil
			}
			err := advisoryBucket.ForEach(func(advisoryID, v []byte) error {
				detail := types.SecurityAdvisory{}
				if err := json.Unmarshal(v, &detail); err != nil {
					return xerrors.Errorf("failed to unmarshall advisory_detail: %w", err)
				}
				securityAdvisory[string(advisoryID)] = detail
				return nil
			})
			SecurityAdvisories[string(platform)] = securityAdvisory
			return err
		})
		if err != nil {
			return xerrors.Errorf("error in db foreach: %w", err)
		}
		return nil
	})
	return SecurityAdvisories, err
}

func (dbc Config) PutSecurityAdvisoryDetails(tx *bolt.Tx, cveId string, osName string, securityAdvisory map[string]types.SecurityAdvisory) error {
	root, err := tx.CreateBucketIfNotExists([]byte(securityAdvisoryBucket))
	if err != nil {
		return err
	}

	cveBucket, err := root.CreateBucketIfNotExists([]byte(cveId))
	if err != nil {
		return err
	}

	osBucket, err := cveBucket.CreateBucketIfNotExists([]byte(osName))
	if err != nil {
		return err
	}

	for secAdvId, advisoryDetail := range securityAdvisory {
		jsonVal, err := json.Marshal(advisoryDetail)
		if err != nil {
			return xerrors.Errorf("failed to marshal JSON: %w", err)
		}
		err = osBucket.Put([]byte(secAdvId), jsonVal)
		if err != nil {
			return err
		}
	}
	return nil
}

func (dbc Config) DeleteSecurityAdvisoryBucket() error {
	return dbc.deleteBucket(securityAdvisoryBucket)
}
