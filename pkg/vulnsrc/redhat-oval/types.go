package redhatoval

type RedhatOVAL struct {
	Class    string
	ID       string
	Version  string
	Metadata Metadata
	Criteria Criteria
}

type Metadata struct {
	Title        string
	AffectedList []Affected
	References   []Reference
	Description  string
	Advisory     Advisory
}

type Advisory struct {
	From            string
	Severity        string
	Rights          string
	Issued          Issued
	Updated         Updated
	Cves            []Cve
	Bugzilla        []Bugzilla
	AffectedCpeList []string
}

type Criteria struct {
	Operator   string
	Criterias  []Criteria
	Criterions []Criterion
}

type Criterion struct {
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

type Issued struct {
	Date string
}

type Updated struct {
	Date string
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
	ID   string
	Href string
}

type Tests struct {
	RpminfoTests []RpminfoTest
}

type Objects struct {
	RpminfoObjects []RpminfoObject
}

type States struct {
	RpminfoState []RpminfoState
}

type State struct {
	Text     string
	StateRef string
}

type Object struct {
	Text      string
	ObjectRef string
}

type RpminfoTest struct {
	Check          string
	Comment        string
	ID             string
	Version        string
	CheckExistence string
	Object         Object
	State          State
}

type RpminfoObject struct {
	ID      string
	Version string
	Name    string
}

type RpminfoState struct {
	ID             string
	Version        string
	Arch           Arch
	Evr            Evr
	SignatureKeyID SignatureKeyID
}

type SignatureKeyID struct {
	Text      string
	Operation string
}

type Arch struct {
	Text      string
	Datatype  string
	Operation string
}

type Evr struct {
	Text      string
	Datatype  string
	Operation string
}

type Package struct {
	Name         string
	FixedVersion string
}
