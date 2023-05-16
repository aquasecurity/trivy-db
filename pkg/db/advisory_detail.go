package db

import (
	"encoding/json"

	ustrings "github.com/aquasecurity/trivy-db/pkg/utils/strings"
	redhatovaltypes "github.com/aquasecurity/trivy-db/pkg/vulnsrc/redhat-oval/types"
	bolt "go.etcd.io/bbolt"

	"golang.org/x/xerrors"
)

const (
	advisoryDetailBucket = "advisory-detail"
)

func (dbc Config) PutAdvisoryDetail(tx *bolt.Tx, vulnID, pkgName string, nestedBktNames []string, advisory interface{}) error {
	bktNames := append([]string{advisoryDetailBucket, vulnID}, nestedBktNames...)
	if err := dbc.put(tx, bktNames, pkgName, advisory); err != nil {
		return xerrors.Errorf("failed to put advisory detail: %w", err)
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
		return xerrors.Errorf("walk advisories error: %w", err)
	}

	return nil
}

// saveAdvisories walks all key-values under the 'advisory-detail' bucket and copy them in each vendor's bucket.
func (dbc Config) saveAdvisories(tx *bolt.Tx, bkt *bolt.Bucket, bktNames []string, vulnID string) error {
	if bkt == nil {
		return nil
	}

	err := bkt.ForEach(func(k, v []byte) error {
		// When the key is a bucket, it walks recursively.
		if v == nil {
			bkts := append(bktNames, string(k))
			if err := dbc.saveAdvisories(tx, bkt.Bucket(k), bkts, vulnID); err != nil {
				return xerrors.Errorf("walk advisories error: %w", err)
			}
		} else {
			detail := map[string]interface{}{}
			if err := json.Unmarshal(v, &detail); err != nil {
				return xerrors.Errorf("failed to unmarshall the advisory detail: %w", err)
			}

			// Put the advisory in vendor's bucket such as Debian and Ubuntu
			bkts := append(bktNames, string(k))
			if err := dbc.put(tx, bkts, vulnID, detail); err != nil {
				return xerrors.Errorf("database put error: %w", err)
			}
		}

		return nil
	})
	if err != nil {
		return xerrors.Errorf("foreach error: %w", err)
	}

	return nil
}

func (dbc Config) DeleteAdvisoryDetailBucket() error {
	return dbc.deleteBucket(advisoryDetailBucket)
}

// SaveRhsaAdvisoryDetails Extract 'RHSA' advisories from 'advisory-detail'-'Red Hat' bucket and copy them in each
func (dbc Config) SaveRhsaAdvisoryDetails(tx *bolt.Tx, vulnID string, rejectedCve []string) error {
	root := tx.Bucket([]byte(advisoryDetailBucket))
	if root == nil {
		return nil
	}

	cveBucket := root.Bucket([]byte(vulnID))
	if cveBucket == nil {
		return nil
	}

	redHatBucket := cveBucket.Bucket([]byte("Red Hat"))
	if redHatBucket == nil {
		return nil
	}

	if err := dbc.saveRhsaAdvisories(tx, redHatBucket, []string{"Red Hat"}, vulnID, rejectedCve); err != nil {
		return xerrors.Errorf("walk advisories error: %w", err)
	}

	return nil
}

// saveRhsaAdvisories walks all RHSA 'advisory-detail' bucket, removes the rejected cve's from the cve List and copy them in each Red Hat bucket.
func (dbc Config) saveRhsaAdvisories(tx *bolt.Tx, bkt *bolt.Bucket, bktNames []string, vulnID string, rejectedCve []string) error {
	if bkt == nil {
		return nil
	}

	err := bkt.ForEach(func(k, v []byte) error {
		advisory := redhatovaltypes.Advisory{}
		if err := json.Unmarshal(v, &advisory); err != nil {
			return xerrors.Errorf("failed to unmarshall the advisory detail: %w", err)
		}

		for i, entry := range advisory.Entries {
			var cves []redhatovaltypes.CveEntry
			for _, cve := range entry.Cves {
				// Include in the database only non-rejected Cves
				if !ustrings.InSlice(cve.ID, rejectedCve) {
					cves = append(cves, cve)
				}
			}
			advisory.Entries[i].Cves = cves
		}

		// Save advisory
		bkts := append(bktNames, string(k))
		if err := dbc.put(tx, bkts, vulnID, advisory); err != nil {
			return xerrors.Errorf("database put error: %w", err)
		}

		return nil
	})
	if err != nil {
		return xerrors.Errorf("foreach error: %w", err)
	}

	return nil
}
