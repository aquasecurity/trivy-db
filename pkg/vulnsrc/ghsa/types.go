package ghsa

type Package struct {
	Ecosystem string
	Name      string
}

type Advisory struct {
	DatabaseId  int
	Id          string
	GhsaId      string
	References  []Reference
	Identifiers []Identifier
	Description string
	Origin      string
	PublishedAt string
	Severity    string
	Summary     string
	UpdatedAt   string
	WithdrawnAt string
	CVSS        GhsaCvss
}

type GhsaCvss struct {
	Score        float64
	VectorString string
}

type Identifier struct {
	Type  string
	Value string
}

type Reference struct {
	Url string
}

type FirstPatchedVersion struct {
	Identifier string
}

type Version struct {
	FirstPatchedVersion    FirstPatchedVersion
	VulnerableVersionRange string
}

type Entry struct {
	Severity  string
	UpdatedAt string
	Package   Package
	Advisory  Advisory
	Versions  []Version
}
