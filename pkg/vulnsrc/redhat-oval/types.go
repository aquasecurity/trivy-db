package redhatoval

import (
	"encoding/json"

	"github.com/aquasecurity/trivy-db/pkg/types"
)

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
	Cves            []ovalCVE
	Bugzilla        []bugzilla
	AffectedCpeList []string
	Affected        affectedState
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

type affectedState struct {
	Resolution affectedResolution
}

type affectedResolution struct {
	State string
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

type ovalCVE struct {
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
	Arches       []string
}

type bucket struct {
	pkgName string
	vulnID  string
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
	Arches       []string     `json:",omitempty"`
	Status       types.Status `json:"-"`

	// For DB size optimization, CPE names will not be stored.
	// CPE indices are stored instead.
	AffectedCPEList    []string `json:"-"`
	AffectedCPEIndices []int    `json:"Affected,omitempty"`
}

// _Entry is an internal struct for Entry to avoid infinite MarshalJSON loop.
type _Entry Entry

type dbEntry struct {
	_Entry
	IntStatus int `json:"Status,omitempty"`
}

// MarshalJSON customizes how an Entry is marshaled to JSON.
func (e *Entry) MarshalJSON() ([]byte, error) {
	entry := dbEntry{
		_Entry:    _Entry(*e),
		IntStatus: int(e.Status),
	}
	return json.Marshal(entry)
}

func (e *Entry) UnmarshalJSON(data []byte) error {
	var entry dbEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return err
	}
	entry._Entry.Status = types.Status(entry.IntStatus)
	*e = Entry(entry._Entry)
	return nil
}

type CveEntry struct {
	ID string `json:",omitempty"`

	// Severity may differ depending on platform even though the advisories resolve the same CVE-ID.
	Severity types.Severity `json:",omitempty"`
}
