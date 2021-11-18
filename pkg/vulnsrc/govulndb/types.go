package govulndb

import "time"

type Ecosystem string
type AffectsRangeType string

type Package struct {
	Name      string    `json:"name"`
	Ecosystem Ecosystem `json:"ecosystem"`
}

type Affects struct {
	Ranges []AffectsRange `json:",omitempty"`
}

type AffectsRange struct {
	Type       AffectsRangeType `json:"type"`
	Introduced string           `json:"introduced"`
	Fixed      string           `json:"fixed"`
}

type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type GoSpecific struct {
	Symbols []string `json:",omitempty"`
	GOOS    []string `json:",omitempty"`
	GOARCH  []string `json:",omitempty"`
	URL     string   `json:"url"`
}

// source: https://github.com/golang/vulndb/blob/e0c00fae09e687ec6febda47ae3bc7552fc7b988/osv/json.go#L125
type Entry struct {
	ID                string      `json:"id"`
	Module            string      `json:"module"`
	Published         time.Time   `json:"published"`
	Modified          time.Time   `json:"modified"`
	Withdrawn         *time.Time  `json:"withdrawn,omitempty"`
	Aliases           []string    `json:"aliases,omitempty"`
	Package           Package     `json:"package"`
	Details           string      `json:"details"`
	Affects           Affects     `json:"affects"`
	References        []Reference `json:"references,omitempty"`
	EcosystemSpecific GoSpecific  `json:"ecosystem_specific"`
}
