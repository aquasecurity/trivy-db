package alpine

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	alpineDir = "alpine"
)

var (
	platformFormat = "alpine %s"
)

type VulnSrc struct {
	dbc db.Operation
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Name() string {
	return vulnerability.Alpine
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", alpineDir)
	var advisories []advisory
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var advisory advisory
		if err := json.NewDecoder(r).Decode(&advisory); err != nil {
			return xerrors.Errorf("failed to decode Alpine advisory: %w", err)
		}
		advisories = append(advisories, advisory)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in Alpine walk: %w", err)
	}

	if err = vs.save(advisories); err != nil {
		return xerrors.Errorf("error in Alpine save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(advisories []advisory) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		for _, advisory := range advisories {
			version := strings.TrimPrefix(advisory.Distroversion, "v")
			platformName := fmt.Sprintf(platformFormat, version)
			if err := vs.saveSecFixes(tx, platformName, advisory.PkgName, advisory.Secfixes); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in db batch update: %w", err)
	}
	return nil
}

func (vs VulnSrc) saveSecFixes(tx *bolt.Tx, platform, pkgName string, secfixes map[string][]string) error {
	for fixedVersion, vulnIDs := range secfixes {
		advisory := types.Advisory{
			FixedVersion: fixedVersion,
		}
		for _, vulnID := range vulnIDs {
			// See https://gitlab.alpinelinux.org/alpine/infra/docker/secdb/-/issues/3
			// e.g. CVE-2017-2616 (+ regression fix)
			ids := strings.Fields(vulnID)
			for _, cveID := range ids {
				cveID = strings.ReplaceAll(cveID, "CVE_", "CVE-")
				if !strings.HasPrefix(cveID, "CVE-") {
					continue
				}
				if err := vs.dbc.PutAdvisoryDetail(tx, cveID, platform, pkgName, advisory); err != nil {
					return xerrors.Errorf("failed to save Alpine advisory: %w", err)
				}

				// for light DB
				if err := vs.dbc.PutSeverity(tx, cveID, types.SeverityUnknown); err != nil {
					return xerrors.Errorf("failed to save Alpine vulnerability severity: %w", err)
				}
			}
		}
	}
	return nil
}

func (vs VulnSrc) Get(release, pkgName string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, release)
	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get Alpine advisories: %w", err)
	}
	return advisories, nil
}
