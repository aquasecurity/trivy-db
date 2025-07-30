package seal

import (
	"encoding/json"
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/types"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
)

func parseCVSSScore(severities []OSVSeverity) float64 {
	for _, s := range severities {
		if s.Type == "CVSS_V3" && s.Score != "" {
			cvssVectorV3 := strings.TrimSuffix(s.Score, "/")
			switch {
			case strings.HasPrefix(cvssVectorV3, "CVSS:3.0"):
				cvss, err := gocvss30.ParseVector(cvssVectorV3)
				if err != nil {
					continue
				}
				return cvss.EnvironmentalScore()
			case strings.HasPrefix(cvssVectorV3, "CVSS:3.1"):
				cvss, err := gocvss31.ParseVector(cvssVectorV3)
				if err != nil {
					continue
				}
				return cvss.EnvironmentalScore()
			}
		}
	}
	return 0.0
}

func cvssScoreToSeverity(cvssScore float64) types.Severity {
	switch {
	case cvssScore >= 9.0:
		return types.SeverityCritical
	case cvssScore >= 7.0:
		return types.SeverityHigh
	case cvssScore >= 4.0:
		return types.SeverityMedium
	case cvssScore > 0.0:
		return types.SeverityLow
	default:
		return types.SeverityUnknown
	}
}

func createOsvAdvisory(data OSVData) types.Advisory {
	return types.Advisory{
		VulnerabilityID:    data.CveID,
		VulnerableVersions: []string{data.VulnVersion},
		PatchedVersions:    []string{data.PatchedVersion},
	}
}

func createRpmAdvisory(data RPMData) types.Advisories {
	return types.Advisories{
		FixedVersion: data.PatchedVersion,
		Entries: []types.Advisory{
			{
				Arches:       []string{data.Arch},
				FixedVersion: data.PatchedVersion,
			},
		},
	}
}

func isOracleEntry(entry OSVEntry) bool {
	if entry.DatabaseSpecific != nil {
		var oracleSpecific OracleDatabaseSpecific
		if err := json.Unmarshal(entry.DatabaseSpecific, &oracleSpecific); err == nil {
			return oracleSpecific.Type == "RPM"
		}
	}
	return false
}

func extractOracleData(entry OSVEntry) (string, string) {
	var patchedVersion, arch string
	if entry.DatabaseSpecific != nil {
		var oracleSpecific OracleDatabaseSpecific
		if err := json.Unmarshal(entry.DatabaseSpecific, &oracleSpecific); err == nil {
			patchedVersion = oracleSpecific.Version
			arch = oracleSpecific.Arch
		}
	}
	return patchedVersion, arch
}

func processOracleEntry(entry OSVEntry, vulnData VulnerabilityData) RPMData {
	patchedVersion, arch := extractOracleData(entry)
	return RPMData{
		VulnerabilityData: vulnData,
		Arch:              arch,
		PatchedVersion:    patchedVersion,
	}
}

func processOsvEntry(affected OSVAffected, vulnData VulnerabilityData) OSVData {
	var vulnVersion, patchedVersion string
	for _, r := range affected.Ranges {
		if r.Type == "ECOSYSTEM" {
			for _, event := range r.Events {
				if event.Introduced != "" {
					vulnVersion = event.Introduced
				}
				if event.Fixed != "" {
					patchedVersion = event.Fixed
				}
			}
		}
	}
	return OSVData{
		VulnerabilityData: vulnData,
		VulnVersion:       vulnVersion,
		PatchedVersion:    patchedVersion,
	}
} 