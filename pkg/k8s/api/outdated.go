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
	K8sOutdatedAPI    types.SourceID = "k8s-outdated-api"
)

type OutdatedApiDb types.OutDatedAPIData

var (
	dataType = "outdated-api"
)

type Outdated struct {
	dbc db.Operation
}

func NewOutdated() Outdated {
	return Outdated{
		dbc: db.Config{},
	}
}

func (vs Outdated) Update(dir string) error {
	rootDir := filepath.Join(dir, "trivy-db-data", "k8s", k8sOutdatedAPiDir)
	var outdatedApiDbs []OutdatedApiDb
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var outdatedApiDb OutdatedApiDb
		if err := json.NewDecoder(r).Decode(&outdatedApiDb); err != nil {
			return xerrors.Errorf("failed to decode k8s outdated api Advisory: %w", err)
		}
		outdatedApiDbs = append(outdatedApiDbs, outdatedApiDb)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in outdated api walk: %w", err)
	}

	if err = vs.save(outdatedApiDbs); err != nil {
		return xerrors.Errorf("error in outdated api save: %w", err)
	}

	return nil
}

func (vs Outdated) save(advisories []OutdatedApiDb) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		for _, adv := range advisories {
			if err := vs.dbc.PutK8sDb(tx, dataType, adv); err != nil {
				return xerrors.Errorf("failed to put outdated API data: %w", err)
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
	var outdatedAPI types.OutDatedAPIData
	err := vs.dbc.GetK8sDb(dataType, &outdatedAPI)
	if err != nil {
		return nil, xerrors.Errorf("failed to get outdated api data: %w", err)
	}
	return outdatedAPI, err
}
