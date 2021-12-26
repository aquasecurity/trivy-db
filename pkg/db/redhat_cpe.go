package db

import (
	"encoding/json"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
)

const (
	redhatCPEBucket = "Red Hat CPE"
)

func (dbc Config) PutRedHatCPEs(tx *bolt.Tx, repository string, cpes []string) error {
	if err := dbc.put(tx, []string{redhatCPEBucket}, repository, cpes); err != nil {
		return xerrors.Errorf("Red Hat CPE error: %w", err)
	}

	return nil
}

func (dbc Config) GetRedHatCPEs(repository string) ([]string, error) {
	value, err := dbc.get([]string{redhatCPEBucket}, repository)
	if err != nil {
		return nil, xerrors.Errorf("unable to get '%s': %w", repository, err)
	} else if len(value) == 0 {
		return nil, nil
	}

	var cpes []string
	if err = json.Unmarshal(value, &cpes); err != nil {
		return nil, xerrors.Errorf("JSON unmarshal error: %w", err)
	}
	return cpes, nil
}
