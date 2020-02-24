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
		return vs.commit(tx, ghsas)
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}

	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, ghsas []GithubSecurityAdvisory) error {
	for _, ghsa := range ghsas {
		platformName := fmt.Sprintf(platformFormat, vs.ecosystem)
		var pvs, avs []string
		for _, va := range ghsa.VersionAdvisories {
			pvs = append(pvs, va.FirstPatchedVersion.Identifier)
			avs = append(avs, va.VulnerableVersionRange)
		}

		vulnId := ghsa.Advisory.GhsaId
		for _, identifier := range ghsa.Advisory.Identifiers {
			if identifier.Type == "CVE" {
				vulnId = identifier.Value
			}
		}

		for index, patchVersion := range pvs {
			// e.g. GHSA-r4x3-g983-9g48 PatchVersion has "<" operator
			if strings.HasPrefix(patchVersion, "<") {
				avs[index] = fmt.Sprintf("%s, %s", avs[index], pvs[index])
			}
		}

		a := types.Advisory{
			VulnerabilityID:    vulnId,
			PatchedVersions:    pvs,
			VulnerableVersions: avs,
		}
		err := vs.dbc.PutAdvisory(tx, platformName, ghsa.Package.Name, vulnId, a)
		if err != nil {
			return xerrors.Errorf("failed to save ghsa: %w", err)
		}

		var references []string
		for _, ref := range ghsa.Advisory.References {
			references = append(references, ref.Url)
		}

		vuln := types.VulnerabilityDetail{
			ID:          vulnId,
			Severity:    severityFromThreat(ghsa.Severity),
			References:  references,
			Title:       ghsa.Advisory.Summary,
			Description: ghsa.Advisory.Description,
		}

		if err = vs.dbc.PutVulnerabilityDetail(tx, vulnId, fmt.Sprintf(datasourceFormat, strings.ToLower(vs.ecosystem.String())), vuln); err != nil {
			return xerrors.Errorf("failed to save ghsa vulnerability detail: %w", err)
		}

		if err := vs.dbc.PutSeverity(tx, vulnId, types.SeverityUnknown); err != nil {
			return xerrors.Errorf("failed to save ghsa vulnerability severity: %w", err)
		}
	}

	return nil
}

func (vs VulnSrc) Get(pkgName string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, vs.ecosystem.String())
	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get ghsa %s vulnerabilities: %w", vs.ecosystem.String(), err)
	}
	return advisories, nil
}

func severityFromThreat(urgency string) types.Severity {
	switch urgency {
	case "LOW":
		return types.SeverityLow

	case "MODERATE":
		return types.SeverityMedium

	case "HIGH":
		return types.SeverityHigh

	case "CRITICAL":
		return types.SeverityCritical
	default:
		return types.SeverityUnknown
	}
}
