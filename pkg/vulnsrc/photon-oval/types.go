package photonoval

// PhotonOVAL represents a Photon OS OVAL advisory JSON file
type PhotonOVAL struct {
	Title       string      `json:"Title"`
	Description string      `json:"Description"`
	Platform    []string    `json:"Platform"`
	References  []Reference `json:"References"`
	Criteria    Criteria    `json:"Criteria"`
	Severity    string      `json:"Severity"`
	Cves        []Cve       `json:"Cves"`
	Issued      Date        `json:"Issued"`
	Updated     Date        `json:"Updated"`
}

// Reference represents a reference link in the advisory
type Reference struct {
	Source string `json:"Source"`
	URI    string `json:"URI"`
	ID     string `json:"ID"`
}

// Cve represents a CVE entry within the advisory
type Cve struct {
	ID string `json:"ID"`
}

// Criteria represents the OVAL criteria tree
type Criteria struct {
	Operator   string     `json:"Operator"`
	Criterias  []Criteria `json:"Criterias"` //nolint:misspell
	Criterions []Criterion `json:"Criterions"`
}

// Criterion represents a single OVAL criterion
type Criterion struct {
	Comment string `json:"Comment"`
}

// Date represents a date in an OVAL advisory
type Date struct {
	Date string `json:"Date"`
}

// AffectedPackage holds a parsed package name and its fixed version
type AffectedPackage struct {
	Name         string
	FixedVersion string
}
