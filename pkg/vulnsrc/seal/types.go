package seal

import (
	"encoding/json"
	"time"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
)

type VulnSrc struct {
	dbc      db.Operation
	sourceID types.SourceID
}

type VulnerabilityData struct {
	CveID          string
	PkgName        string
	Bucket         string
	DataSourceName string
	DataSourceURL  string
	Title          string
	Description    string
	Reference      string
	CvssScore      float64
	Published      string
	LastModified   string
	Severity       types.Severity
}

type OSVData struct {
	VulnerabilityData
	VulnVersion    string
	PatchedVersion string
}

type RPMData struct {
	VulnerabilityData
	Arch           string
	PatchedVersion string
}

type SealAdvisory struct {
	CveID          string  `json:"cve_id"`
	PkgName        string  `json:"pkg_name"`
	Bucket         string  `json:"bucket"`
	DataSourceName string  `json:"data_source_name"`
	DataSourceURL  string  `json:"data_source_url"`
	Title          string  `json:"title"`
	Description    string  `json:"description"`
	Reference      string  `json:"reference"`
	CvssScore      float64 `json:"cvss_score"`
	Published      string  `json:"published"`
	LastModified   string  `json:"last_modified"`
	Severity       string  `json:"severity"`
	Type           string  `json:"type"` // "osv" or "rpm"
	VulnVersion    string  `json:"vuln_version,omitempty"`
	PatchedVersion string  `json:"patched_version,omitempty"`
	Arch           string  `json:"arch,omitempty"`
}

// OSV-specific structures for parsing seal-vulnerabilities-osv.json
type OSVEntry struct {
	SchemaVersion    string          `json:"schema_version,omitempty"`
	ID               string          `json:"id"`
	Modified         time.Time       `json:"modified,omitempty"`
	Published        time.Time       `json:"published,omitempty"`
	Withdrawn        *time.Time      `json:"withdrawn,omitempty"`
	Aliases          []string        `json:"aliases,omitempty"`
	Summary          string          `json:"summary,omitempty"`
	Details          string          `json:"details"`
	Severities       []OSVSeverity   `json:"severities"`
	Affected         []OSVAffected   `json:"affected"`
	References       []OSVReference  `json:"references,omitempty"`
	DatabaseSpecific json.RawMessage `json:"database_specific,omitempty"`
}

type OSVSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type OSVAffected struct {
	Package           OSVPackage           `json:"package"`
	Severities        []OSVSeverity        `json:"severity,omitempty"`
	Ranges            []OSVRange           `json:"ranges,omitempty"`
	Versions          []string             `json:"versions,omitempty"`
	EcosystemSpecific OSVEcosystemSpecific `json:"ecosystem_specific"`
	DatabaseSpecific  json.RawMessage      `json:"database_specific,omitempty"`
}

type OSVPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type OSVRange struct {
	Type   string       `json:"type"`
	Events []OSVEvent   `json:"events"`
}

type OSVEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

type OSVReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type OSVEcosystemSpecific struct {
	Imports []OSVImport `json:"imports,omitempty"`
}

type OSVImport struct {
	Path    string   `json:"path,omitempty"`
	GOOS    []string `json:"goos,omitempty"`
	GOARCH  []string `json:"goarch,omitempty"`
	Symbols []string `json:"symbols,omitempty"`
}

type OSVDatabaseSpecific struct {
	Source string `json:"source"`
	Type   string `json:"type"`
}

type OracleDatabaseSpecific struct {
	Version string `json:"version"`
	Arch    string `json:"arch"`
	Source  string `json:"source"`
	Type    string `json:"type"`
} 