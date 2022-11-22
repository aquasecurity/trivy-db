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
	alpineDir      = "alpine"
	platformFormat = "alpine %s"
)

var (
	alpineSource = types.DataSource{
		ID:   vulnerability.Alpine,
		Name: "Alpine Secdb",
		URL:  "https://secdb.alpinelinux.org/",
	}
)

type option func(c *VulnSrc)

func WithPlatformFormat(frmt string) option {
	return func(src *VulnSrc) {
		src.platformFormat = frmt
	}
}
func WithSource(dataSrc types.DataSource) option {
	return func(src *VulnSrc) {
		src.source = dataSrc
	}
}

func WithDir(dir string) option {
	return func(src *VulnSrc) {
		src.distroDir = dir
	}
}

type VulnSrc struct {
	dbc            db.Operation
	distroDir      string
	source         types.DataSource
	platformFormat string
}

func NewVulnSrc(options ...option) VulnSrc {
	src := VulnSrc{
		dbc:            db.Config{},
		distroDir:      alpineDir,
		source:         alpineSource,
		platformFormat: platformFormat,
	}
	for _, opt := range options {
		opt(&src)
	}
	return src
}

func (vs VulnSrc) Name() types.SourceID {
	return vs.source.ID
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", vs.distroDir)
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
		for _, adv := range advisories {
			version := strings.TrimPrefix(adv.Distroversion, "v")
			platformName := fmt.Sprintf(vs.platformFormat, version)
			if err := vs.dbc.PutDataSource(tx, platformName, vs.source); err != nil {
				return xerrors.Errorf("failed to put data source: %w", err)
			}
			if err := vs.saveSecFixes(tx, platformName, adv.PkgName, adv.Secfixes); err != nil {
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
				if err := vs.dbc.PutAdvisoryDetail(tx, cveID, pkgName, []string{platform}, advisory); err != nil {
					return xerrors.Errorf("failed to save Alpine advisory: %w", err)
				}

				// for optimization
				if err := vs.dbc.PutVulnerabilityID(tx, cveID); err != nil {
					return xerrors.Errorf("failed to save the vulnerability ID: %w", err)
				}
			}
		}
	}
	return nil
}

func (vs VulnSrc) Get(release, pkgName string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(vs.platformFormat, release)
	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get Alpine advisories: %w", err)
	}
	return advisories, nil
}
