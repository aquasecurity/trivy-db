package db

import (
	"encoding/json"

	"github.com/aquasecurity/trivy-db/pkg/types"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
)

func (dbc Config) PutAdvisory(tx *bolt.Tx, bktNames []string, key string, advisory interface{}) error {
	if err := dbc.put(tx, bktNames, key, advisory); err != nil {
		return xerrors.Errorf("failed to put advisory: %w", err)
	}
	return nil
}

func (dbc Config) ForEachAdvisory(source, pkgName string) (value map[string][]byte, err error) {
	return dbc.forEach(source, pkgName)
}

func (dbc Config) GetAdvisories(source, pkgName string) ([]types.Advisory, error) {
	advisories, err := dbc.ForEachAdvisory(source, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("advisory foreach error: %w", err)
	}
	if len(advisories) == 0 {
		return nil, nil
	}

	var results []types.Advisory
	for vulnID, v := range advisories {
		var advisory types.Advisory
		if err = json.Unmarshal(v, &advisory); err != nil {
			return nil, xerrors.Errorf("failed to unmarshal advisory JSON: %w", err)
		}
		advisory.VulnerabilityID = vulnID
		results = append(results, advisory)
	}
	return results, nil
}
