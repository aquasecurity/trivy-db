package osv

import (
	"time"
)

type RangeType string

const RangeTypeGit RangeType = "GIT"

type Ecosystem string

// Module identifies the Go module containing the vulnerability.
// Note that this field is called "package" in the OSV specification.
//
// See https://ossf.github.io/osv-schema/#affectedpackage-field.
type Module struct {
	Path      string    `json:"name"`
	Ecosystem Ecosystem `json:"ecosystem"`
}

type RangeEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
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

type Affected struct {
	// The affected Go module. Required.
	// Note that this field is called "package" in the OSV specification.
	Module            Module            `json:"package"`
	Ranges            []Range           `json:"ranges,omitempty"`
	EcosystemSpecific EcosystemSpecific `json:"ecosystem_specific"`
}

type Package struct {
	Path    string   `json:"path,omitempty"`
	GOOS    []string `json:"goos,omitempty"`
	GOARCH  []string `json:"goarch,omitempty"`
	Symbols []string `json:"symbols,omitempty"`
}

type EcosystemSpecific struct {
	Packages []Package `json:"imports,omitempty"`
}

// source: https://github.com/golang/vuln/blob/2e18a6705c6b7f63b802491a33e8b78766cb3822/internal/osv/osv.go
type Entry struct {
	SchemaVersion    string            `json:"schema_version,omitempty"`
	ID               string            `json:"id"`
	Modified         time.Time         `json:"modified,omitempty"`
	Published        time.Time         `json:"published,omitempty"`
	Withdrawn        *time.Time        `json:"withdrawn,omitempty"`
	Aliases          []string          `json:"aliases,omitempty"`
	Summary          string            `json:"summary,omitempty"`
	Details          string            `json:"details"`
	Affected         []Affected        `json:"affected"`
	References       []Reference       `json:"references,omitempty"`
	Credits          []Credit          `json:"credits,omitempty"`
	DatabaseSpecific *DatabaseSpecific `json:"database_specific,omitempty"`
}

type Credit struct {
	Name string `json:"name"`
}

type DatabaseSpecific struct {
	URL string `json:"url,omitempty"`
}
