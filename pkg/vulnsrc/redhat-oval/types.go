package redhatoval

import "github.com/aquasecurity/trivy-db/pkg/types"

type redhatOVAL struct {
	Class    string
	ID       string
	Version  string
	Metadata ovalMetadata
	Criteria criteria
}

type ovalMetadata struct {
	Title        string
	AffectedList []affected
	References   []reference
	Description  string
	Advisory     ovalAdvisory
}

type ovalAdvisory struct {
	From            string
	Severity        string
	Rights          string
	Issued          issued
	Updated         updated
	Cves            []cve
	Bugzilla        []bugzilla
	AffectedCpeList []string
}

type criteria struct {
	Operator   string
	Criterias  []criteria
	Criterions []criterion
}

type criterion struct {
	TestRef string
	Comment string
}

type affected struct {
	Family    string
	Platforms []string
}

type reference struct {
	Source string
	RefID  string
	RefURL string
}

type issued struct {
	Date string
}

type updated struct {
	Date string
}

type cve struct {
	CveID  string
	Cvss2  string
	Cvss3  string
	Cwe    string
	Impact string
	Href   string
	Public string
}

type bugzilla struct {
	ID   string
	Href string
}

type ovalTests struct {
	RpminfoTests []rpminfoTest
}

type ovalObjects struct {
	RpminfoObjects []rpminfoObject
}

type ovalStates struct {
	RpminfoState []rpminfoState
}

type ovalstate struct {
	Text     string
	StateRef string
}

type ovalObject struct {
	Text      string
	ObjectRef string
}

type rpminfoTest struct {
	Check          string
	Comment        string
	ID             string
	Version        string
	CheckExistence string
	Object         ovalObject
	State          ovalstate
}

type rpminfoObject struct {
	ID      string
	Version string
	Name    string
}

type rpminfoState struct {
	ID             string
	Version        string
	Arch           arch
	Evr            evr
	SignatureKeyID signatureKeyID
}

type signatureKeyID struct {
	Text      string
	Operation string
}

type arch struct {
	Text      string
	Datatype  string
	Operation string
}

type evr struct {
	Text      string
	Datatype  string
	Operation string
}

type pkg struct {
	Name         string
	FixedVersion string
}

type bucket struct {
	platform string
	pkgName  string
	cveID    string
}

type vulnerabilityDetail struct {
	bucket
	definition Definition
}

type Definition struct {
	FixedVersion    string   `json:",omitempty"`
	AffectedCPEList []string `json:",omitempty"`
	AdvisoryID      string   `json:",omitempty"`
}

type advisory struct {
	types.Advisory              // for backward compatibility and CentOS
	Definitions    []Definition `json:",omitempty"` // RHEL uses this field
}

type repositoryToCPE struct {
	Data map[string]struct {
		Cpes []string `json:"cpes"`
	} `json:"data"`
}
