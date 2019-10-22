package debian

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/types"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	bolt "github.com/etcd-io/bbolt"
	"golang.org/x/xerrors"
)

const (
	debianDir = "debian"
)

var (
	// e.g. debian 8
	platformFormat        = "debian %s"
	DebianReleasesMapping = map[string]string{
		// Code names
		"squeeze": "6",
		"wheezy":  "7",
		"jessie":  "8",
		"stretch": "9",
		"buster":  "10",
		"sid":     "unstable",
	}
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
	rootDir := filepath.Join(dir, debianDir)
	var cves []DebianCVE
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var cve DebianCVE
		if err := json.NewDecoder(r).Decode(&cve); err != nil {
			return xerrors.Errorf("failed to decode Debian JSON: %w", err)
		}

		cve.VulnerabilityID = strings.TrimSuffix(filepath.Base(path), ".json")
		cve.Package = filepath.Base(filepath.Dir(path))
		cves = append(cves, cve)

		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in Debian walk: %w", err)
	}

	if err = vs.save(cves); err != nil {
		return xerrors.Errorf("error in Debian save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(cves []DebianCVE) error {
	log.Println("Saving Debian DB")
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		for _, cve := range cves {
			for _, release := range cve.Releases {
				for releaseStr := range release.Repositories {
					majorVersion, ok := DebianReleasesMapping[releaseStr]
					if !ok {
						continue
					}
					platformName := fmt.Sprintf(platformFormat, majorVersion)
					if release.Status != "open" {
						continue
					}
					advisory := types.Advisory{
						VulnerabilityID: cve.VulnerabilityID,
						//Severity:        severityFromUrgency(release.Urgency),
					}
					if err := vs.dbc.PutAdvisory(tx, platformName, cve.Package, cve.VulnerabilityID, advisory); err != nil {
						return xerrors.Errorf("failed to save Debian advisory: %w", err)
					}

					vuln := types.VulnerabilityDetail{
						Severity:    severityFromUrgency(release.Urgency),
						Description: cve.Description,
					}
					if err := vs.dbc.PutVulnerabilityDetail(tx, cve.VulnerabilityID, vulnerability.Debian, vuln); err != nil {
						return xerrors.Errorf("failed to save Debian vulnerability: %w", err)
					}

					// for light DB
					if err := vs.dbc.PutSeverity(tx, cve.VulnerabilityID, types.SeverityUnknown); err != nil {
						return xerrors.Errorf("failed to save alpine vulnerability severity: %w", err)
					}
				}
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
	advisories, err := vs.dbc.ForEachAdvisory(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("error in Debian foreach: %w", err)
	}
	if len(advisories) == 0 {
		return nil, nil
	}

	var results []types.Advisory
	for _, v := range advisories {
		var advisory types.Advisory
		if err = json.Unmarshal(v, &advisory); err != nil {
			return nil, xerrors.Errorf("failed to unmarshal Debian JSON: %w", err)
		}
		results = append(results, advisory)
	}
	return results, nil
}

func severityFromUrgency(urgency string) types.Severity {
	switch urgency {
	case "not yet assigned":
		return types.SeverityUnknown

	case "end-of-life", "unimportant", "low", "low*", "low**":
		return types.SeverityLow

	case "medium", "medium*", "medium**":
		return types.SeverityMedium

	case "high", "high*", "high**":
		return types.SeverityHigh
	default:
		return types.SeverityUnknown
	}
}
