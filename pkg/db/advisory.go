package db

import (
	"encoding/json"

	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/types"
)

func (dbc Config) PutAdvisory(tx *bolt.Tx, bktNames []string, key string, advisory interface{}) error {
	if err := dbc.put(tx, bktNames, key, advisory); err != nil {
		return oops.With("key", key).Wrapf(err, "failed to put advisory")
	}
	return nil
}

func (dbc Config) ForEachAdvisory(sources []string, pkgName string) (map[string]Value, error) {
	return dbc.forEach(append(sources, pkgName))
}

func (dbc Config) GetAdvisories(source, pkgName string) ([]types.Advisory, error) {
	eb := oops.With("source", source).With("package_name", pkgName)
	advisories, err := dbc.ForEachAdvisory([]string{source}, pkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "advisory foreach error")
	}
	if len(advisories) == 0 {
		return nil, nil
	}

	var results []types.Advisory
	for vulnID, v := range advisories {
		var advisory types.Advisory
		if err = json.Unmarshal(v.Content, &advisory); err != nil {
			return nil, eb.With("vuln_id", vulnID).Wrapf(err, "json unmarshal error")
		}

		advisory.VulnerabilityID = vulnID
		if v.Source != (types.DataSource{}) {
			advisory.DataSource = &types.DataSource{
				ID:   v.Source.ID,
				Name: v.Source.Name,
				URL:  v.Source.URL,
			}
		}

		results = append(results, advisory)
	}
	return results, nil
}
