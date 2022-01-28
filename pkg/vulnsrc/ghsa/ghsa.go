package ghsa

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
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
	ghsaDir = "ghsa"

	Composer Ecosystem = iota + 1
	Maven
	Npm
	Nuget
	Pip
	RubyGems
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
	case RubyGems:
		return "RubyGems"
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

func (vs VulnSrc) Name() string {
	switch vs.ecosystem {
	case Composer:
		return vulnerability.GHSAComposer
	case Maven:
		return vulnerability.GHSAMaven
	case Npm:
		return vulnerability.GHSANpm
	case Nuget:
		return vulnerability.GHSANuget
	case Pip:
		return vulnerability.GHSAPip
	case RubyGems:
		return vulnerability.GHSARubygems
	}
	return ""
}

func (vs VulnSrc) Update(dir string) error {
	var ghsas []GithubSecurityAdvisory

	rootDir := filepath.Join(dir, "vuln-list", ghsaDir)
	err := utils.FileWalk(filepath.Join(rootDir, strings.ToLower(vs.ecosystem.String())), func(r io.Reader, path string) error {
		var ghsa GithubSecurityAdvisory
		if err := json.NewDecoder(r).Decode(&ghsa); err != nil {
			return xerrors.Errorf("failed to decode GHSA: %w", err)
		}
		ghsas = append(ghsas, ghsa)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in GHSA walk: %w", err)
	}

	if err = vs.save(ghsas); err != nil {
		return xerrors.Errorf("error in GHSA save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(ghsas []GithubSecurityAdvisory) error {
	log.Println("Saving GHSA DB")
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return vs.commit(tx, ghsas)
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}

	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, ghsas []GithubSecurityAdvisory) error {
	platformName := fmt.Sprintf(platformFormat, vs.ecosystem)
	err := vs.dbc.PutDataSource(tx, platformName, types.DataSource{
		Name: fmt.Sprintf("GitHub Advisory Database %s", vs.ecosystem),
		URL: fmt.Sprintf("https://github.com/advisories?query=type%%3Areviewed+ecosystem%%3A%s",
			strings.ToLower(vs.ecosystem.String())),
	})
	if err != nil {
		return xerrors.Errorf("failed to put data source: %w", err)
	}

	for _, ghsa := range ghsas {
		if ghsa.Advisory.WithdrawnAt != "" {
			continue
		}
		var pvs, avs []string
		for _, va := range ghsa.Versions {
			// e.g. GHSA-r4x3-g983-9g48 PatchVersion has "<" operator
			if strings.HasPrefix(va.FirstPatchedVersion.Identifier, "<") {
				va.VulnerableVersionRange = fmt.Sprintf(
					"%s, %s",
					va.VulnerableVersionRange,
					va.FirstPatchedVersion.Identifier,
				)
				va.FirstPatchedVersion.Identifier = strings.TrimPrefix(va.FirstPatchedVersion.Identifier, "< ")
			}

			if va.FirstPatchedVersion.Identifier != "" {
				pvs = append(pvs, va.FirstPatchedVersion.Identifier)
			}
			avs = append(avs, va.VulnerableVersionRange)
		}

		vulnID := ghsa.Advisory.GhsaId
		for _, identifier := range ghsa.Advisory.Identifiers {
			if identifier.Type == "CVE" && identifier.Value != "" {
				vulnID = identifier.Value
			}
		}
		vulnID = strings.TrimSpace(vulnID)

		a := types.Advisory{
			PatchedVersions:    pvs,
			VulnerableVersions: avs,
		}

		pkgName := vs.ToLowerCasePackage(ghsa.Package.Name)

		err = vs.dbc.PutAdvisoryDetail(tx, vulnID, pkgName, []string{platformName}, a)
		if err != nil {
			return xerrors.Errorf("failed to save GHSA: %w", err)
		}

		var references []string
		for _, ref := range ghsa.Advisory.References {
			references = append(references, ref.Url)
		}

		vuln := types.VulnerabilityDetail{
			ID:          vulnID,
			Severity:    severityFromThreat(ghsa.Severity),
			References:  references,
			Title:       ghsa.Advisory.Summary,
			Description: ghsa.Advisory.Description,
		}

		if err = vs.dbc.PutVulnerabilityDetail(tx, vulnID, fmt.Sprintf(datasourceFormat, strings.ToLower(vs.ecosystem.String())), vuln); err != nil {
			return xerrors.Errorf("failed to save GHSA vulnerability detail: %w", err)
		}

		// for optimization
		if err = vs.dbc.PutVulnerabilityID(tx, vulnID); err != nil {
			return xerrors.Errorf("failed to save the vulnerability ID: %w", err)
		}
	}

	return nil
}

func (vs VulnSrc) Get(pkgName string) ([]types.Advisory, error) {
	pkgName = vs.ToLowerCasePackage(pkgName)

	bucket := fmt.Sprintf(platformFormat, vs.ecosystem.String())
	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("GHSA advisory error: %w", err)
	}

	return advisories, nil
}

func (vs VulnSrc) ToLowerCasePackage(pkgName string) string {
	if vs.ecosystem == Pip {
		/*
			  from https://www.python.org/dev/peps/pep-0426/#name
				All comparisons of distribution names MUST be case insensitive, and MUST consider hyphens and underscores to be equivalent.
		*/
		pkgName = toLowerCasePythonPackage(pkgName)
	} else if vs.ecosystem != Nuget { // Nuget is case-sensitive
		pkgName = strings.ToLower(pkgName)
	}
	return pkgName
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

func toLowerCasePythonPackage(pkg string) string {
	/*
		  from https://www.python.org/dev/peps/pep-0426/#name
			All comparisons of distribution names MUST be case insensitive, and MUST consider hyphens and underscores to be equivalent.
	*/
	pkg = strings.ToLower(pkg)
	pkg = strings.ReplaceAll(pkg, "_", "-")
	return pkg
}
