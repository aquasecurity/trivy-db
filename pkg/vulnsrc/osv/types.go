package osv

type OSV struct {
	ID         string      `json:"id,omitempty"`
	Modified   string      `json:"modified,omitempty"`
	Published  string      `json:"published,omitempty"`
	Aliases    []string    `json:"aliases,omitempty"`
	Summary    string      `json:"summary,omitempty"`
	Details    string      `json:"details,omitempty"`
	Affected   []Affected  `json:"affected,omitempty"`
	References []Reference `json:"references,omitempty"`
}

type Affected struct {
	Package  *Package `json:"package,omitempty"`
	Ranges   []Range  `json:"ranges,omitempty"`
	Versions []string `json:"versions,omitempty"`
}
type Package struct {
	Name string `json:"name,omitempty"`
}
type Range struct {
	Type   string  `json:"type,omitempty"`
	Repo   string  `json:"repo,omitempty"`
	Events []Event `json:"events,omitempty"`
}
type Event struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type Reference struct {
	Type string `json:"type,omitempty"`
	Url  string `json:"url,omitempty"`
}
