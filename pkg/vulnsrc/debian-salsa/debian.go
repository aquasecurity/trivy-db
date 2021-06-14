package debian

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/aquasecurity/trivy-db/pkg/types"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
)

const (
	debianDir = "debian-salsa"
)

var (
	// e.g. debian 8
	platformFormat        = "debian-salsa %s"
	DebianReleasesMapping = map[string]string{
		// Code names
		"squeeze":  "6",
		"wheezy":   "7",
		"jessie":   "8",
		"stretch":  "9",
		"buster":   "10",
		"unstable": "unstable",
		"bullseye": "bullseye",
	}
)

type VulnSrc struct {
	dbc db.Operation
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", debianDir)
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
		return vs.commit(tx, cves)
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}

	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, cves []DebianCVE) error {
	for _, cve := range cves {
		for releaseName, release := range cve.Releases {
			majorVersion, ok := DebianReleasesMapping[releaseName]
			if !ok {
				continue
			}
			platformName := fmt.Sprintf(platformFormat, majorVersion)
			// Advisory IDs
			var advisoryIds []string
			for secAdvId, _ := range release.SecurityAdvisory {
				advisoryIds = append(advisoryIds, secAdvId)
			}
			advisory := types.Advisory{
				FixedVersion:     release.FixVersion,
				WillNotFix:       release.WillNotFix,
				SecurityAdvisory: advisoryIds,
			}
			if err := vs.dbc.PutAdvisoryDetail(tx, cve.VulnerabilityID, platformName, cve.Package, advisory); err != nil {
				return xerrors.Errorf("failed to save Debian advisory: %w", err)
			}

			vuln := types.VulnerabilityDetail{
				Severity:    severityFromUrgency(release.Severity),
				Description: cve.Description,
			}
			if err := vs.dbc.PutVulnerabilityDetail(tx, cve.VulnerabilityID, vulnerability.Debian, vuln); err != nil {
				return xerrors.Errorf("failed to save Debian vulnerability: %w", err)
			}
			// Save Security Advisory details
			if len(release.SecurityAdvisory) > 0 {
				securityAdvisories := make(map[string]types.SecurityAdvisory)
				for advId, advisory := range release.SecurityAdvisory {
					secAdvisory := types.SecurityAdvisory{}
					publishDate, err := time.Parse("2006-01-02 15:04:05 +0000 UTC", advisory.PublishDate)
					if err != nil {
						log.Println("Error in publish Date, %w", err)
					}
					secAdvisory.PublishDate = publishDate
					secAdvisory.Description = advisory.Description
					securityAdvisories[advId] = secAdvisory
				}
				if err := vs.dbc.PutSecurityAdvisoryDetails(tx, cve.VulnerabilityID, vulnerability.Debian, securityAdvisories); err != nil {
					return xerrors.Errorf("failed to save Debian vulnerability: %w", err)
				}
			}
			// for light DB
			if err := vs.dbc.PutSeverity(tx, cve.VulnerabilityID, types.SeverityUnknown); err != nil {
				return xerrors.Errorf("failed to save Debian vulnerability severity: %w", err)
			}
		}
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

func severityFromUrgency(urgency string) types.Severity {
	switch urgency {
	case "not yet assigned", "end-of-life":
		return types.SeverityUnknown

	case "unimportant", "low", "low*", "low**":
		return types.SeverityLow

	case "medium", "medium*", "medium**":
		return types.SeverityMedium

	case "high", "high*", "high**":
		return types.SeverityHigh
	default:
		return types.SeverityUnknown
	}
}
