package osv

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	vtypes "github.com/aquasecurity/vuln-list-update/osv"
)

const (
	osvDir         = "osv"
	platformFormat = "Osv Security Advisories %s"

	//ecosystem names
	Python = "PyPI"
	Go     = "Go"
	Rust   = "crates.io"
)

var defaultEcosystems = map[string]ecosystem{
	Python: {dir: "python", dataSource: vulnerability.OsvPyPI, eventType: "ECOSYSTEM", firstVersion: "0"},
	Go:     {dir: "go", dataSource: vulnerability.OsvGo, eventType: "SEMVER", firstVersion: "0"},
	Rust:   {dir: "rust", dataSource: vulnerability.OsvCratesio, eventType: "SEMVER", firstVersion: "0.0.0-0"},
}

type ecosystem struct {
	dir          string
	dataSource   string
	eventType    string
	firstVersion string
}

type VulnSrc struct {
	ecosystem ecosystem
	dbc       db.Operation
}

func NewVulnSrc(ecosystemName string) VulnSrc {
	ecosystem := defaultEcosystems[ecosystemName]
	return VulnSrc{
		ecosystem: ecosystem,
		dbc:       db.Config{},
	}
}

func (vs VulnSrc) Name() string {
	for name, ecosystem := range defaultEcosystems {
		if ecosystem.dataSource == vs.ecosystem.dataSource {
			return name
		}
	}
	return ""
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", osvDir, vs.ecosystem.dir)

	var osvs []vtypes.OsvJson

	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var osv vtypes.OsvJson
		if err := json.NewDecoder(r).Decode(&osv); err != nil {
			return xerrors.Errorf("failed to decode osv json (%s): %w", path, err)
		}
		osvs = append(osvs, osv)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in osv walk: %w", err)
	}

	if err = vs.save(osvs); err != nil {
		return xerrors.Errorf("error in osv save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(osvs []vtypes.OsvJson) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, osvs)
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, osvs []vtypes.OsvJson) error {
	for _, osv := range osvs {
		vulnId := getVulnId(&osv)

		for _, affected := range osv.Affected {
			var vulnerableVersions []string
			var patchedVersions []string

			firstVersion := vs.ecosystem.firstVersion
			if len(affected.Versions) != 0 && affected.Versions[0] != "" {
				firstVersion = affected.Versions[0]
			}

			for _, rng := range affected.Ranges {
				if rng.Type == vs.ecosystem.eventType {
					var vulnerableVersion string

					for _, event := range rng.Events {
						if event.Fixed != "" && event.Introduced != "" { //fixed and introduced in 1 struct
							patchedVersions = append(patchedVersions, event.Fixed)
							vulnerableVersions = append(vulnerableVersions, fmt.Sprintf(">=%s <%s", event.Introduced, event.Fixed))
						} else if event.Introduced != "" {
							if vulnerableVersion != "" {
								vulnerableVersions = append(vulnerableVersions, vulnerableVersion)
							}
							vulnerableVersion = fmt.Sprintf(">=%s", event.Introduced)
						} else if event.Fixed != "" {
							if vulnerableVersion != "" {
								vulnerableVersion = vulnerableVersion + fmt.Sprintf(" <%s", event.Fixed)
							} else {
								vulnerableVersion = fmt.Sprintf(">=%s <%s", firstVersion, event.Fixed)
							}
							patchedVersions = append(patchedVersions, event.Fixed)
						}
					}
					if vulnerableVersion != "" {
						vulnerableVersions = append(vulnerableVersions, vulnerableVersion)
					}
				}
			}

			advisory := types.Advisory{
				VulnerableVersions: vulnerableVersions,
				PatchedVersions:    patchedVersions,
			}

			if err := vs.dbc.PutAdvisoryDetail(tx, vulnId, fmt.Sprintf(platformFormat, vs.Name()), affected.Package.Name, advisory); err != nil {
				return xerrors.Errorf("failed to save osv advisory: %w", err)
			}

			var references []string
			for _, ref := range osv.References {
				references = append(references, ref.Url)
			}

			vuln := types.VulnerabilityDetail{
				ID:               vulnId,
				Description:      osv.Details,
				PublishedDate:    mustParse(time.RFC3339, osv.Published),
				LastModifiedDate: mustParse(time.RFC3339Nano, osv.Modified),
				Title:            osv.Id,
				References:       references,
			}

			if err := vs.dbc.PutVulnerabilityDetail(tx, vulnId, vs.ecosystem.dataSource, vuln); err != nil {
				return xerrors.Errorf("failed to save osv vulnerability: %w", err)
			}

			// for light DB
			if err := vs.dbc.PutSeverity(tx, vulnId, types.SeverityUnknown); err != nil {
				return xerrors.Errorf("failed to save osv vulnerability severity for light: %w", err)
			}
		}
	}
	return nil
}

func (vs VulnSrc) Get(pkgName string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, vs.Name())
	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get Osv advisories: %w", err)
	}
	return advisories, nil

}

func getVulnId(osv *vtypes.OsvJson) string {
	if len(osv.Aliases) == 0 {
		return osv.Id
	} else {
		return osv.Aliases[0] //CVE Id
	}
}

func mustParse(layout, value string) *time.Time {
	t, err := time.Parse(layout, value)
	if err != nil {
		return nil
	}
	return &t
}
