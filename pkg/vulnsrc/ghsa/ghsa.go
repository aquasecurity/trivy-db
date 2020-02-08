package ghsa

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
	bolt "github.com/etcd-io/bbolt"
	"golang.org/x/xerrors"
)

const (
	ghsaDir = "ghsa"

	Composer Ecosystem = iota
	Maven
	Npm
	Nuget
	Pip
	Rubygems
)

type Ecosystem int

func (e Ecosystem) String() string {
	switch e {
	case Composer:
		return "Composer"
	case Maven:
		return "Maven"
	case Npm:
		return "Npm"
	case Nuget:
		return "Nuget"
	case Pip:
		return "Pip"
	case Rubygems:
		return "Rubygems"
	}
	return "Unknown"
}

var (
	datasourceFormat = "ghsa-%s"
	platformFormat   = "GitHub Security Advisory %s"
)

type VulnSrc struct {
	dbc       db.Operation
	ecosystem Ecosystem
}

func NewVulnSrc(ecosystem Ecosystem) VulnSrc {
	return VulnSrc{
		dbc:       db.Config{},
		ecosystem: ecosystem,
	}
}

func (vs VulnSrc) Update(dir string) error {
	var ghsas []GithubSecurityAdvisory

	rootDir := filepath.Join(dir, "vuln-list", ghsaDir)
	err := utils.FileWalk(filepath.Join(rootDir, strings.ToLower(vs.ecosystem.String())), func(r io.Reader, path string) error {
		var ghsa GithubSecurityAdvisory
		if err := json.NewDecoder(r).Decode(&ghsa); err != nil {
			return xerrors.Errorf("failed to decode Ghsa Advisory: %w", err)
		}
		ghsas = append(ghsas, ghsa)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in Ghsa walk: %w", err)
	}

	if err = vs.save(ghsas); err != nil {
		return xerrors.Errorf("error in Ghsa save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(ghsas []GithubSecurityAdvisory) error {
	log.Println("Saving Ghsa DB")
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		for _, ghsa := range ghsas {
			platformName := fmt.Sprintf(platformFormat, vs.ecosystem)
			var pvs, avs []string
			for _, va := range ghsa.VersionAdvisories {
				pvs = append(pvs, va.FirstPatchedVersion.Identifier)
				avs = append(avs, va.VulnerableVersionRange)
			}
			a := Advisory{
				VulnerabilityID:    ghsa.Advisory.GhsaId,
				PatchedVersions:    pvs,
				VulnerableVersions: avs,
			}
			err := vs.dbc.PutAdvisory(tx, platformName, ghsa.Package.Name, ghsa.Advisory.GhsaId, a)
			if err != nil {
				return xerrors.Errorf("failed to save ruby advisory: %w", err)
			}

			var references []string
			for _, ref := range ghsa.Advisory.References {
				references = append(references, ref.Url)
			}
			vuln := types.VulnerabilityDetail{
				ID:          ghsa.Advisory.GhsaId,
				Severity:    severityFromThreat(ghsa.Severity),
				References:  references,
				Title:       ghsa.Advisory.Summary,
				Description: ghsa.Advisory.Description,
			}
			if err = vs.dbc.PutVulnerabilityDetail(tx, ghsa.Advisory.GhsaId, fmt.Sprintf(datasourceFormat, strings.ToLower(vs.ecosystem.String())), vuln); err != nil {
				return xerrors.Errorf("failed to save ghsa vulnerability detail: %w", err)
			}

			if err := vs.dbc.PutSeverity(tx, ghsa.Advisory.GhsaId, types.SeverityUnknown); err != nil {
				return xerrors.Errorf("failed to save ghsa vulnerability severity: %w", err)
			}

		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}

	return nil
}

func (vs VulnSrc) Get(pkgName string) ([]Advisory, error) {
	advisories, err := vs.dbc.ForEachAdvisory(fmt.Sprintf(datasourceFormat, vs.ecosystem), pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to iterate php vulnerabilities: %w", err)
	}

	var results []Advisory
	for vulnID, a := range advisories {
		var advisory Advisory
		if err = json.Unmarshal(a, &advisory); err != nil {
			return nil, xerrors.Errorf("failed to unmarshal advisory JSON: %w", err)
		}
		advisory.VulnerabilityID = vulnID
		results = append(results, advisory)
	}
	return results, nil
}

func severityFromThreat(urgency string) types.Severity {
	switch urgency {
	case "Low":
		return types.SeverityLow

	case "Moderate":
		return types.SeverityMedium

	case "High":
		return types.SeverityHigh

	case "Critical":
		return types.SeverityCritical
	default:
		return types.SeverityUnknown
	}
}
