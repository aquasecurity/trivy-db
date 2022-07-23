package api

import (
	"encoding/json"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
	"io"
	"path/filepath"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
)

const (
	k8sOutdatedAPiDir                = "api"
	K8sOutdatedAPI    types.SourceID = "outdated-api"
)

type Advisory types.OutDatedAPIData

var (
	dataSource = "outdatedapi-data-source"
	dataType   = "outdated-api"

	source = types.DataSource{
		ID:   K8sOutdatedAPI,
		Name: "Kubernetes GitHub docs",
		URL:  "https://github/kubernetes/kubernetes",
	}
)

type Outdated struct {
	dbc db.Operation
}

func NewOutdated() Outdated {
	return Outdated{
		dbc: db.Config{},
	}
}

func (vs Outdated) Name() types.SourceID {
	return source.ID
}

func (vs Outdated) Update(dir string) error {
	rootDir := filepath.Join(dir, "trivy-db-data", "k8s", k8sOutdatedAPiDir)
	var advisories []Advisory
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var advisory Advisory
		if err := json.NewDecoder(r).Decode(&advisory); err != nil {
			return xerrors.Errorf("failed to decode k8s outdated api Advisory: %w", err)
		}
		advisories = append(advisories, advisory)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in outdated api walk: %w", err)
	}

	if err = vs.save(advisories); err != nil {
		return xerrors.Errorf("error in outdated api save: %w", err)
	}

	return nil
}

func (vs Outdated) save(advisories []Advisory) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		if err := vs.dbc.PutK8sDataSource(tx, dataSource, source); err != nil {
			return err
		}
		for _, adv := range advisories {
			if err := vs.dbc.PutK8sOutdatedAPI(tx, dataType, adv); err != nil {
				return xerrors.Errorf("failed to put data source: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in db batch update: %w", err)
	}
	return nil
}

func (vs Outdated) Get() (types.OutDatedAPIData, error) {
	outDatedAPIData, err := vs.dbc.GetK8sOutdatedAPI(dataType)
	if err != nil {
		return nil, xerrors.Errorf("failed to get outdated api data: %w", err)
	}
	return outDatedAPIData, nil
}
