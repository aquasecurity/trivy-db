package db

import (
	"encoding/json"
	"strconv"

	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"
)

const (
	redhatCPERootBucket = "Red Hat CPE"
	redhatRepoBucket    = "repository"
	redhatNVRBucket     = "nvr"

	// This bucket will not be used during vulnerability scanning. Just for debugging.
	redhatCPEBucket = "cpe"
)

func (dbc Config) PutRedHatRepositories(tx *bolt.Tx, repository string, cpeIndices []int) error {
	if err := dbc.put(tx, []string{redhatCPERootBucket, redhatRepoBucket}, repository, cpeIndices); err != nil {
		return oops.With("repository", repository).Wrapf(err, "failed to put Red Hat repositories")
	}

	return nil
}

func (dbc Config) PutRedHatNVRs(tx *bolt.Tx, nvr string, cpeIndices []int) error {
	if err := dbc.put(tx, []string{redhatCPERootBucket, redhatNVRBucket}, nvr, cpeIndices); err != nil {
		return oops.With("nvr", nvr).Wrapf(err, "failed to put Red Hat NVRs")
	}

	return nil
}

func (dbc Config) PutRedHatCPEs(tx *bolt.Tx, cpeIndex int, cpe string) error {
	index := strconv.Itoa(cpeIndex)
	if err := dbc.put(tx, []string{redhatCPERootBucket, redhatCPEBucket}, index, cpe); err != nil {
		return oops.With("cpe_index", cpeIndex).With("cpe", cpe).Wrapf(err, "failed to put Red Hat CPEs")
	}

	return nil
}

func (dbc Config) RedHatRepoToCPEs(repository string) ([]int, error) {
	return dbc.getCPEs(redhatRepoBucket, repository)
}

func (dbc Config) RedHatNVRToCPEs(repository string) ([]int, error) {
	return dbc.getCPEs(redhatNVRBucket, repository)
}

func (dbc Config) getCPEs(bucket, key string) ([]int, error) {
	eb := oops.With("bucket_name", bucket).With("key", key)
	value, err := dbc.get([]string{redhatCPERootBucket, bucket}, key)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get CPEs")
	} else if len(value) == 0 {
		return nil, nil
	}

	var cpes []int
	if err = json.Unmarshal(value, &cpes); err != nil {
		return nil, eb.Wrapf(err, "json unmarshal error")
	}
	return cpes, nil
}

// GetAllRedHatCPEs returns all stored CPE strings ordered by their index.
// This is used to merge CSAF CPEs with existing OVAL CPEs.
func (dbc Config) GetAllRedHatCPEs(tx *bolt.Tx) ([]string, error) {
	root := tx.Bucket([]byte(redhatCPERootBucket))
	if root == nil {
		return nil, nil
	}
	cpeBucket := root.Bucket([]byte(redhatCPEBucket))
	if cpeBucket == nil {
		return nil, nil
	}
	// BoltDB iterates keys in lexicographic order ("0","1","10","2",...),
	// so we parse each key as an integer and assign by index directly.
	var result []string
	err := cpeBucket.ForEach(func(k, v []byte) error {
		index, err := strconv.Atoi(string(k))
		if err != nil {
			return oops.Wrapf(err, "invalid CPE index key: %s", string(k))
		}
		var cpe string
		if err := json.Unmarshal(v, &cpe); err != nil {
			return oops.Wrapf(err, "failed to unmarshal CPE value")
		}
		for len(result) <= index {
			result = append(result, "")
		}
		result[index] = cpe
		return nil
	})
	if err != nil {
		return nil, oops.Wrapf(err, "failed to iterate CPE bucket")
	}
	return result, nil
}
