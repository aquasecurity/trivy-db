package alpine

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"

	"github.com/aquasecurity/trivy-db/pkg/types"

	bolt "github.com/etcd-io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
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
	dbc db.Operations
}

func NewVulnSrc() types.VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, alpineDir)
	var cves []AlpineCVE
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var cve AlpineCVE
		if err := json.NewDecoder(r).Decode(&cve); err != nil {
			return xerrors.Errorf("failed to decode Alpine JSON: %w", err)
		}
		cves = append(cves, cve)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in Alpine walk: %w", err)
	}

	if err = vs.save(cves); err != nil {
		return xerrors.Errorf("error in Alpine save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(cves []AlpineCVE) error {
	log.Println("Saving Alpine DB")

	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		for _, cve := range cves {
			platformName := fmt.Sprintf(platformFormat, cve.Release)
			pkgName := cve.Package
			advisory := Advisory{
				VulnerabilityID: cve.VulnerabilityID,
				FixedVersion:    cve.FixedVersion,
				Repository:      cve.Repository,
			}
			if err := vs.dbc.PutAdvisory(tx, platformName, pkgName, cve.VulnerabilityID, advisory); err != nil {
				return xerrors.Errorf("failed to save alpine advisory: %w", err)
			}

			vuln := types.VulnerabilityDetail{
				Title:       cve.Subject,
				Description: cve.Description,
			}
			if err := vs.dbc.PutVulnerabilityDetail(tx, cve.VulnerabilityID, vulnerability.Alpine, vuln); err != nil {
				return xerrors.Errorf("failed to save alpine vulnerability: %w", err)
			}

			// for light DB
			if err := vs.dbc.PutSeverity(tx, cve.VulnerabilityID, types.SeverityUnknown); err != nil {
				return xerrors.Errorf("failed to save alpine vulnerability severity: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in db batch update: %w", err)
	}
	return nil
}

func (vs VulnSrc) Get(release string, pkgName string) ([]Advisory, error) {
	source := fmt.Sprintf(platformFormat, release)
	advisories, err := vs.dbc.ForEachAdvisory(source, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("error in Alpine foreach: %w", err)
	}

	var results []Advisory
	for _, v := range advisories {
		var advisory Advisory
		if err = json.Unmarshal(v, &advisory); err != nil {
			return nil, xerrors.Errorf("failed to unmarshal Alpine JSON: %w", err)
		}
		results = append(results, advisory)
	}
	return results, nil
}
