package api

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/trivy-db/pkg/k8ssrc"
	"io"
	"path/filepath"
	"strings"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
)

const (
	k8sOutdatedAPiDir = "alpine"
)

var (
	platformFormat = "alpine %s"

	source = types.DataSource{
		ID:   k8ssrc.K8sOutdatedAPI,
		Name: "Kubernetes GitHub docs",
		URL:  "https://github/kubernetes/kubernetes",
	}
)

type OutDatedAPI struct {
	dbc db.Operation
}

func NewOutDatedAPI() OutDatedAPI {
	return OutDatedAPI{
		dbc: db.Config{},
	}
}

func (vs OutDatedAPI) Name() types.SourceID {
	return source.ID
}

func (vs OutDatedAPI) Update(dir string) error {
	rootDir := filepath.Join(dir, "k8s", "api", k8sOutdatedAPiDir)
	var advisories []advisory
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var advisory advisory
		if err := json.NewDecoder(r).Decode(&advisory); err != nil {
			return xerrors.Errorf("failed to decode outdated api advisory: %w", err)
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

func (vs OutDatedAPI) save(advisories []advisory) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		for _, adv := range advisories {
			version := strings.TrimPrefix(adv.Distroversion, "v")
			platformName := fmt.Sprintf(platformFormat, version)
			if err := vs.dbc.PutDataSource(tx, platformName, source); err != nil {
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

func (vs OutDatedAPI) Get(release, pkgName string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, release)
	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get Alpine advisories: %w", err)
	}
	return advisories, nil
}
