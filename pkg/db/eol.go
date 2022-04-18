package db

import (
	"encoding/json"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
	"time"
)

const eofBucket = "eol"

func (dbc Config) PutEndOfLifeDates(tx *bolt.Tx, os string, dateList map[string]time.Time) error {
	if err := dbc.put(tx, []string{eofBucket}, os, dateList); err != nil {
		return xerrors.Errorf("failed to put list of end-of-life dates: %w", err)
	}
	return nil
}

func (dbc Config) GetEndOfLifeDates(os string) (dateList map[string]time.Time, err error) {
	err = db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(eofBucket))
		value := bucket.Get([]byte(os))
		if value == nil {
			return xerrors.Errorf("no end-of-life date list for %q", os)
		}
		if err = json.Unmarshal(value, &dateList); err != nil {
			return xerrors.Errorf("failed to unmarshal JSON: %w", err)
		}
		return nil
	})
	if err != nil {
		return make(map[string]time.Time), xerrors.Errorf("failed to get end-of-life date list for %q: %w", os, err)
	}
	return dateList, nil
}
