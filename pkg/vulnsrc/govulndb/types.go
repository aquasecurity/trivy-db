package govulndb

import "time"

type Ecosystem string
type AffectsRangeType int

type Package struct {
	Name      string
	Ecosystem Ecosystem
}

type Affects struct {
	Ranges []AffectsRange `json:",omitempty"`
}

type AffectsRange struct {
	Type       AffectsRangeType
	Introduced string
	Fixed      string
}

type Reference struct {
	Type string
	URL  string
}

type GoSpecific struct {
	Symbols []string `json:",omitempty"`
	GOOS    []string `json:",omitempty"`
	GOARCH  []string `json:",omitempty"`
	URL     string
}

// source: https://github.com/golang/vulndb/blob/e0c00fae09e687ec6febda47ae3bc7552fc7b988/osv/json.go#L125
type Entry struct {
	ID         string
	Module     string
	Published  time.Time
	Modified   time.Time
	Withdrawn  *time.Time `json:",omitempty"`
	Aliases    []string   `json:",omitempty"`
	Package    Package
	Details    string
	Affects    Affects
	References []Reference `json:",omitempty"`
	Extra      struct {
		Go GoSpecific
	}
}
