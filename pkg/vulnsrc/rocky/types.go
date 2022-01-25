package rocky

// RLSA has detailed data of RLSA
type RLSA struct {
	ID          string      `json:"id,omitempty"`
	Title       string      `json:"title,omitempty"`
	Severity    string      `json:"severity,omitempty"`
	Description string      `json:"description,omitempty"`
	PkgLists    []PkgList   `json:"pkglists,omitempty"`
	References  []Reference `json:"references,omitempty"`
	CveIDs      []string    `json:"cveids,omitempty"`
}

// Reference has reference information
type Reference struct {
	Href  string `json:"href,omitempty"`
	ID    string `json:"id,omitempty"`
	Title string `json:"title,omitempty"`
	Type  string `json:"type,omitempty"`
}

// PkgList has modular package information
type PkgList struct {
	Packages []Package `json:"packages,omitempty"`
	Module   Module    `json:"module,omitempty"`
}

// Package has affected package information
type Package struct {
	Name     string `json:"name,omitempty"`
	Epoch    string `json:"epoch,omitempty"`
	Version  string `json:"version,omitempty"`
	Release  string `json:"release,omitempty"`
	Arch     string `json:"arch,omitempty"`
	Filename string `json:"filename,omitempty"`
}

// Module has module information
type Module struct {
	Stream  string `json:"stream,omitempty"`
	Name    string `json:"name,omitempty"`
	Version int64  `json:"version,omitempty"`
	Arch    string `json:"arch,omitempty"`
	Context string `json:"context,omitempty"`
}
