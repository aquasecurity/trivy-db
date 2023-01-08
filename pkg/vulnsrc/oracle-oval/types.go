package oracleoval

type bucket struct {
	platform string
	vulnID   string
	pkgName  string
}

type OracleOVAL struct {
	Title       string
	Description string
	Platform    []string
	References  []Reference
	Criteria    Criteria
	Severity    string
	Cves        []Cve
}

type Reference struct {
	Source string
	URI    string
	ID     string
}

type Cve struct {
	Impact string
	Href   string
	ID     string
}

type Criteria struct {
	Operator   string
	Criterias  []Criteria
	Criterions []Criterion
}

type Criterion struct {
	Comment string
}

type Package struct {
	Name         string
	FixedVersion string
}

type AffectedPackage struct {
	Package Package
	OSVer   string
}

type Advisory struct {
	Entries []Entry `json:",omitempty"`
	// Backwards compatibility.  Eventually could be removed
	FixedVersion string `json:",omitempty"`
}

// Entry holds the unique advisory information per package flavor
type Entry struct {
	FixedVersion string   `json:",omitempty"`
	VendorIDs    []string `json:",omitempty"`
}

type PackageFlavor int

const (
	PackageFlavorNormal PackageFlavor = iota
	PackageFlavorFips
	PackageFlavorKsplice
)
