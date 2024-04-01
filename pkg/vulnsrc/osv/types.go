package osv

import (
	"encoding/json"
	"time"
)

const (
	RangeTypeGit RangeType = "GIT"

	EcosystemGo        Ecosystem = "Go"
	EcosystemNpm       Ecosystem = "npm"
	EcosystemPyPI      Ecosystem = "PyPI"
	EcosystemRubygems  Ecosystem = "RubyGems"
	EcosystemCrates    Ecosystem = "crates.io"
	EcosystemPackagist Ecosystem = "Packagist"
	EcosystemMaven     Ecosystem = "Maven"
	EcosystemNuGet     Ecosystem = "NuGet"
)

type Ecosystem string
type RangeType string

type Package struct {
	Name      string    `json:"name"`
	Ecosystem Ecosystem `json:"ecosystem"`
}

type RangeEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

type Range struct {
	Type   RangeType    `json:"type"`
	Events []RangeEvent `json:"events"`
}

type ReferenceType string

type Reference struct {
	Type ReferenceType `json:"type"`
	URL  string        `json:"url"`
}

type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type Affected struct {
	Package           Package           `json:"package"`
	Severities        []Severity        `json:"severity,omitempty"`
	Ranges            []Range           `json:"ranges,omitempty"`
	Versions          []string          `json:"versions,omitempty"`
	EcosystemSpecific EcosystemSpecific `json:"ecosystem_specific"`
	DatabaseSpecific  json.RawMessage   `json:"database_specific,omitempty"`
}

type Import struct {
	Path    string   `json:"path,omitempty"`
	GOOS    []string `json:"goos,omitempty"`
	GOARCH  []string `json:"goarch,omitempty"`
	Symbols []string `json:"symbols,omitempty"`
}

type EcosystemSpecific struct {
	Imports []Import `json:"imports,omitempty"`
}

// source: https://ossf.github.io/osv-schema
type Entry struct {
	SchemaVersion    string          `json:"schema_version,omitempty"`
	ID               string          `json:"id"`
	Modified         time.Time       `json:"modified,omitempty"`
	Published        time.Time       `json:"published,omitempty"`
	Withdrawn        *time.Time      `json:"withdrawn,omitempty"`
	Aliases          []string        `json:"aliases,omitempty"`
	Summary          string          `json:"summary,omitempty"`
	Details          string          `json:"details"`
	Severities       []Severity      `json:"severity"`
	Affected         []Affected      `json:"affected"`
	References       []Reference     `json:"references,omitempty"`
	Credits          []Credit        `json:"credits,omitempty"`
	DatabaseSpecific json.RawMessage `json:"database_specific,omitempty"`
}

type Credit struct {
	Name string `json:"name"`
}
