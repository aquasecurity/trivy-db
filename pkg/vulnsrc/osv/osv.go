package osv

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
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
	osvDir           = "osv"
	datasourceFormat = "osv-%s"
	platformFormat   = "Osv Security Advisories %s"

	//ecosystem names
	Python = "PyPI"
	Go     = "Go"
	Rust   = "crates.io"
)

var defaultEcosystem = []ecosystem{
	{name: Python, dir: "python", eventType: "ECOSYSTEM", firstVersion: "0"},
	{name: Go, dir: "go", eventType: "SEMVER", firstVersion: "0"},
	{name: Rust, dir: "rust", eventType: "SEMVER", firstVersion: "0.0.0-0"},
}

type ecosystem struct {
	name         string
	dir          string
	eventType    string
	firstVersion string
}

type VulnSrc struct {
	ecosystem ecosystem
	dbc       db.Operation
}

func NewVulnSrc(ecosystemName string) VulnSrc {
	ecosystem := getEcoSystem(ecosystemName)
	return VulnSrc{
		ecosystem: ecosystem,
		dbc:       db.Config{},
	}
}

func (vs VulnSrc) Name() string {
	switch vs.ecosystem.name {
	case "PyPI":
		return vulnerability.OsvPyPI
	case "Go":
		return vulnerability.OsvGo
	case "crates.io":
		return vulnerability.OsvCratesio
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

			if err := vs.dbc.PutAdvisoryDetail(tx, vulnId, fmt.Sprintf(platformFormat, vs.ecosystem.name), affected.Package.Name, advisory); err != nil {
				return xerrors.Errorf("failed to save osv advisory: %w", err)
			}

			var references []string
			for _, ref := range osv.References {
				references = append(references, ref.Url)
			}

			vuln := types.VulnerabilityDetail{
				ID:               vulnId,
				Description:      osv.Details,
				PublishedDate:    MustParse(time.RFC3339, osv.Published),
				LastModifiedDate: MustParse(time.RFC3339Nano, osv.Modified),
				Title:            osv.Id,
				References:       references,
			}

			if err := vs.dbc.PutVulnerabilityDetail(tx, vulnId, fmt.Sprintf(datasourceFormat, strings.ToLower(vs.ecosystem.name)), vuln); err != nil {
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

func getEcoSystem(ecosystemName string) ecosystem {
	for _, system := range defaultEcosystem {
		if system.name == ecosystemName {
			return system
		}
	}
	return ecosystem{}
}

func (vs VulnSrc) Get(pkgName string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, vs.ecosystem.name)
	advisories, err := vs.dbc.ForEachAdvisory(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to iterate Osv: %w", err)
	}

	var results []types.Advisory
	for vulnID, a := range advisories {
		var advisory types.Advisory
		if err = json.Unmarshal(a, &advisory); err != nil {
			return nil, xerrors.Errorf("failed to unmarshal advisory JSON: %w", err)
		}
		advisory.VulnerabilityID = vulnID
		results = append(results, advisory)
	}
	return results, nil
}

func getVulnId(osv *vtypes.OsvJson) string {
	if len(osv.Aliases) == 0 {
		return osv.Id
	} else {
		return osv.Aliases[0] //CVE Id
	}
}

func MustParse(layout, value string) *time.Time {
	t, err := time.Parse(layout, value)
	if err != nil {
		return nil
	}
	return &t
}
