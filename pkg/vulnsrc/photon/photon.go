package photon

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"

	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	photonDir      = "photon"
	platformFormat = "Photon OS %s"
)

var source = types.DataSource{
	ID:   vulnerability.Photon,
	Name: "Photon OS CVE metadata",
	URL:  "https://packages.vmware.com/photon/photon_cve_metadata/",
}

type VulnSrc struct {
	dbc    db.Operation
	logger *log.Logger
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc:    db.Config{},
		logger: log.WithPrefix("photon"),
	}
}

func (vs VulnSrc) Name() types.SourceID {
	return source.ID
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", photonDir)
	eb := oops.In("photon").With("root_dir", rootDir)

	var cves []PhotonCVE
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var cve PhotonCVE
		if err := json.NewDecoder(r).Decode(&cve); err != nil {
			return eb.With("file_path", path).Wrapf(err, "json decode error")
		}
		cves = append(cves, cve)

		return nil
	})
	if err != nil {
		return eb.Wrapf(err, "walk error")
	}

	if err = vs.save(cves); err != nil {
		return eb.Wrapf(err, "save error")
	}

	return nil
}

func (vs VulnSrc) save(cves []PhotonCVE) error {
	vs.logger.Info("Saving DB")
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, cves)
	})
	if err != nil {
		return oops.Wrapf(err, "batch update error")
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, cves []PhotonCVE) error {
	for _, cve := range cves {
		platformName := fmt.Sprintf(platformFormat, cve.OSVersion)
		if err := vs.dbc.PutDataSource(tx, platformName, source); err != nil {
			return oops.Wrapf(err, "failed to put data source")
		}

		advisory := types.Advisory{
			FixedVersion: cve.ResVer,
		}
		if err := vs.dbc.PutAdvisoryDetail(tx, cve.CveID, cve.Pkg, []string{platformName}, advisory); err != nil {
			return oops.Wrapf(err, "failed to save advisory")
		}

		vuln := types.VulnerabilityDetail{
			// Photon uses CVSS Version 3.X
			CvssScoreV3: cve.CveScore,
		}
		if err := vs.dbc.PutVulnerabilityDetail(tx, cve.CveID, source.ID, vuln); err != nil {
			return oops.Wrapf(err, "failed to save vulnerability detail")
		}

		// for optimization
		if err := vs.dbc.PutVulnerabilityID(tx, cve.CveID); err != nil {
			return oops.Wrapf(err, "failed to save vulnerability ID")
		}
	}
	return nil
}

func (vs VulnSrc) Get(release string, pkgName string) ([]types.Advisory, error) {
	eb := oops.In("photon").With("release", release)
	bucket := fmt.Sprintf(platformFormat, release)
	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get advisories")
	}
	return advisories, nil
}
