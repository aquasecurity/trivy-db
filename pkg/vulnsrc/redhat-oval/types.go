package redhatoval

type RedhatOVAL struct {
	ID          string
	Class       string
	Title       string
	Affecteds   []Affected
	References  []Reference
	Description string
	Advisory    Advisory
	Criteria    Criteria
}

type Criteria struct {
	Operator   string
	Criterias  []Criteria
	Criterions []Criterion
}

type Criterion struct {
	Negate  bool
	TestRef string
	Comment string
}

type Affected struct {
	Family    string
	Platforms []string
}

type Reference struct {
	Source string
	RefID  string
	RefURL string
}

type Advisory struct {
	Severity        string
	Cves            []Cve
	Bugzillas       []Bugzilla
	AffectedCPEList []string
	Issued          struct{ Date string }
	Updated         struct{ Date string }
}

type Cve struct {
	CveID  string
	Cvss2  string
	Cvss3  string
	Cwe    string
	Impact string
	Href   string
	Public string
}

type Bugzilla struct {
	ID    string
	URL   string
	Title string
}

type Package struct {
	Name         string
	FixedVersion string
}
