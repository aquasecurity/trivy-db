package oracleoval

import "github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"

type OracleOVAL struct {
	Title       string
	Description string
	Platform    []string
	References  []Reference
	Criteria    Criteria
	Severity    string
	Cves        []Cve
	IssuedDate  Date `json:"issued,omitempty"`
}

type Reference struct {
	Source string
	URI    string
	ID     string
}

type Cve struct {
	Impact string
	Href   string
	Public string
	// Oracle encodes cvss2 and cvss3 as "score/vector" (e.g. cvss3="7.3/CVSS:3.1/AV:N/...").
	// Stored verbatim; downstream consumers split into score/vector themselves.
	CVSS2 string
	CVSS3 string
	ID    string
}

type Criteria struct {
	Operator   string
	Criterias  []Criteria //nolint:misspell
	Criterions []Criterion
}

type Criterion struct {
	Comment string
}

type Package struct {
	Name  string
	OSVer string
}

type AffectedPackage struct {
	Package      Package
	Arch         string
	FixedVersion string
}

type Date struct {
	Date string `json:"date"`
}

func (p *Package) PlatformName() string {
	return bucket.NewOracle(p.OSVer).Name()
}
