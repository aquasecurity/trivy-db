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
	value, err := dbc.get([]string{eofBucket}, os)
	if err = json.Unmarshal(value, &dateList); err != nil {
		return make(map[string]time.Time), xerrors.Errorf("failed to get list of end-of-life dates for %q: %w", os, err)
	}

	return dateList, nil
}
