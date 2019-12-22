package photon

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	bolt "github.com/etcd-io/bbolt"
	"golang.org/x/xerrors"
)

const (
	photonDir      = "photon"
	platformFormat = "Photon OS %s"
)

type VulnSrc struct {
	dbc db.Operations
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", photonDir)

	var cves []PhotonCVE
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var cve PhotonCVE
		if err := json.NewDecoder(r).Decode(&cve); err != nil {
			return xerrors.Errorf("failed to decode Photon JSON: %w", err)
		}
		cves = append(cves, cve)

		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in Photon walk: %w", err)
	}

	if err = vs.save(cves); err != nil {
		return xerrors.Errorf("error in Photon save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(cves []PhotonCVE) error {
	log.Println("Saving Photon DB")
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		for _, cve := range cves {
			platformName := fmt.Sprintf(platformFormat, cve.OSVersion)
			advisory := types.Advisory{
				VulnerabilityID: cve.CveID,
				FixedVersion:    cve.ResVer,
			}
			if err := vs.dbc.PutAdvisory(tx, platformName, cve.Pkg, cve.CveID, advisory); err != nil {
				return xerrors.Errorf("failed to save Debian advisory: %w", err)
			}
			severity := vulnerability.ScoreToSeverity(cve.CveScore)
			vuln := types.VulnerabilityDetail{
				Severity:    severity,
				Description: cve.AffVer,
			}
			if err := vs.dbc.PutVulnerabilityDetail(tx, cve.CveID, vulnerability.Photon, vuln); err != nil {
				return xerrors.Errorf("failed to save Debian vulnerability: %w", err)
			}

			// for light DB
			if err := vs.dbc.PutSeverity(tx, cve.CveID, severity); err != nil {
				return xerrors.Errorf("failed to save alpine vulnerability severity: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}

	return nil
}

func (vs VulnSrc) Get(release string, pkgName string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, release)
	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get Debian advisories: %w", err)
	}
	return advisories, nil
}
