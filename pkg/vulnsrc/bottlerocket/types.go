package bottlerocket

// Advisory represents a single Bottlerocket security advisory.
type Advisory struct {
	Title       string      `json:"title,omitempty"`
	Severity    string      `json:"severity,omitempty"`
	Description string      `json:"description,omitempty"`
	Packages    []Package   `json:"packages,omitempty"`
	References  []Reference `json:"references,omitempty"`
}

// Package holds an affected/fixed package.
type Package struct {
	Name    string `json:"name,omitempty"`
	Epoch   string `json:"epoch,omitempty"`
	Version string `json:"version,omitempty"`
	Release string `json:"release,omitempty"`
}

// Reference holds a vulnerability reference (CVE, GHSA, BRSA, etc.).
type Reference struct {
	Href string `json:"href,omitempty"`
	ID   string `json:"id,omitempty"`
	Type string `json:"type,omitempty"`
}
