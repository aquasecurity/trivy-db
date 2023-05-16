package types

import "github.com/aquasecurity/trivy-db/pkg/types"

type RedhatOVAL struct {
	Class    string
	ID       string
	Version  string
	Metadata OvalMetadata
	Criteria Criteria
}

type OvalMetadata struct {
	Title        string
	AffectedList []Affected
	References   []Reference
	Description  string
	Advisory     OvalAdvisory
}

type OvalAdvisory struct {
	From            string
	Severity        string
	Rights          string
	Issued          Issued
	Updated         Updated
	Cves            []OvalCVE
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

type OvalCVE struct {
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

type OvalTests struct {
	RpminfoTests []RpminfoTest
}

type OvalObjects struct {
	RpminfoObjects []RpminfoObject
}

type OvalStates struct {
	RpminfoState []RpminfoState
}

type Ovalstate struct {
	Text     string
	StateRef string
}

type OvalObject struct {
	Text      string
	ObjectRef string
}

type RpminfoTest struct {
	Check          string
	Comment        string
	ID             string
	Version        string
	CheckExistence string
	Object         OvalObject
	State          Ovalstate
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

type Pkg struct {
	Name         string
	FixedVersion string
	Arches       []string
}

type Bucket struct {
	PkgName string
	VulnID  string
}

type Advisory struct {
	Entries []Entry `json:",omitempty"`
}

type Definition struct {
	Entry Entry `json:",omitempty"`
}

// Entry holds the unique advisory information per platform.
type Entry struct {
	FixedVersion string `json:",omitempty"`
	Cves         []CveEntry
	Arches       []string `json:",omitempty"`

	// For DB size optimization, CPE names will not be stored.
	// CPE indices are stored instead.
	AffectedCPEList    []string `json:"-"`
	AffectedCPEIndices []int    `json:"Affected,omitempty"`
}

type CveEntry struct {
	ID string `json:",omitempty"`

	// Severity may differ depending on platform even though the advisories resolve the same CVE-ID.
	Severity types.Severity `json:",omitempty"`
}
