package alt

import (
	"github.com/aquasecurity/trivy-db/pkg/types"
)

type Definitions struct {
	Definition []Definition `json:",omitempty"`
}

type Definition struct {
	ID       string   `json:",omitempty"`
	Version  string   `json:",omitempty"`
	Class    string   `json:",omitempty"`
	Metadata Metadata `json:",omitempty"`
	Criteria Criteria `json:",omitempty"`
}

type Metadata struct {
	Title        string      `json:",omitempty"`
	AffectedList []Affected  `json:",omitempty"`
	References   []Reference `json:",omitempty"`
	Description  string      `json:",omitempty"`
	Advisory     Advisory    `json:",omitempty"`
}

type Affected struct {
	Family    string   `json:",omitempty"`
	Platforms []string `json:",omitempty"`
	Products  []string `json:",omitempty"`
}

type Reference struct {
	RefID  string `json:",omitempty"`
	RefURL string `json:",omitempty"`
	Source string `json:",omitempty"`
}

type Advisory struct {
	From         string       `json:",omitempty"`
	Severity     string       `json:",omitempty"`
	Rights       string       `json:",omitempty"`
	Issued       Issued       `json:",omitempty"`
	Updated      Updated      `json:",omitempty"`
	BDUs         []CVE        `json:",omitempty"`
	CVEs         []CVE        `json:",omitempty"`
	Bugzilla     []Bugzilla   `json:",omitempty"`
	AffectedCPEs AffectedCPEs `json:",omitempty"`
}

type Bugzilla struct {
	ID   string `json:",omitempty"`
	Href string `json:",omitempty"`
	Data string `json:",omitempty"`
}

type Issued struct {
	Date string `json:",omitempty"`
}

type Updated struct {
	Date string `json:",omitempty"`
}

type CVE struct {
	ID     string `json:",omitempty"`
	CVSS   string `json:",omitempty"`
	CVSS3  string `json:",omitempty"`
	CWE    string `json:",omitempty"`
	Href   string `json:",omitempty"`
	Impact string `json:",omitempty"`
	Public string `json:",omitempty"`
}

type AffectedCPEs struct {
	CPEs []string `json:",omitempty"`
}

type Criteria struct {
	Operator   string      `json:",omitempty"`
	Criterions []Criterion `json:",omitempty"`
	Criterias  []Criteria  `json:",omitempty"`
}

type Criterion struct {
	TestRef string `json:",omitempty"`
	Comment string `json:",omitempty"`
}

type Tests struct {
	TextFileContent54Tests []TextFileContent54Test `json:",omitempty"`
	RPMInfoTests           []RPMInfoTest           `json:",omitempty"`
}

type TextFileContent54Test struct {
	ID      string `json:",omitempty"`
	Version string `json:",omitempty"`
	Check   string `json:",omitempty"`
	Comment string `json:",omitempty"`
	Object  Object `json:",omitempty"`
	State   State  `json:",omitempty"`
}

type State struct {
	StateRef string `json:",omitempty"`
	Text     string `json:",omitempty"`
}

type Object struct {
	ObjectRef string `json:",omitempty"`
	Text      string `json:",omitempty"`
}

type RPMInfoTest struct {
	ID      string `json:",omitempty"`
	Version string `json:",omitempty"`
	Check   string `json:",omitempty"`
	Comment string `json:",omitempty"`
	Object  Object `json:",omitempty"`
	State   State  `json:",omitempty"`
}

type RPMInfoObject struct {
	ID      string `json:",omitempty"`
	Version string `json:",omitempty"`
	Comment string `json:",omitempty"`
	Name    string `json:",omitempty"`
}

type RPMInfoState struct {
	ID            string        `json:",omitempty"`
	Version       string        `json:",omitempty"`
	Comment       string        `json:",omitempty"`
	Arch          Arch          `json:",omitempty"`
	EVR           EVR           `json:",omitempty"`
	Subexpression Subexpression `json:",omitempty"`
}

type Arch struct {
	Text      string `json:",omitempty"`
	Datatype  string `json:",omitempty"`
	Operation string `json:",omitempty"`
}

type EVR struct {
	Text      string `json:",omitempty"`
	Datatype  string `json:",omitempty"`
	Operation string `json:",omitempty"`
}

type Subexpression struct {
	Operation string `json:",omitempty"`
	Text      string `json:",omitempty"`
}

type Objects struct {
	TextFileContent54Objects []TextFileContent54Object `json:",omitempty"`
	RPMInfoObjects           []RPMInfoObject           `json:",omitempty"`
}

type TextFileContent54Object struct {
	ID       string   `json:",omitempty"`
	Version  string   `json:",omitempty"`
	Comment  string   `json:",omitempty"`
	Path     Path     `json:",omitempty"`
	Filepath Filepath `json:",omitempty"`
	Pattern  Pattern  `json:",omitempty"`
	Instance Instance `json:",omitempty"`
}

type Path struct {
	Datatype string `json:",omitempty"`
	Text     string `json:",omitempty"`
}

type Filepath struct {
	Datatype string `json:",omitempty"`
	Text     string `json:",omitempty"`
}

type Pattern struct {
	Datatype  string `json:",omitempty"`
	Operation string `json:",omitempty"`
	Text      string `json:",omitempty"`
}

type Instance struct {
	Datatype string `json:",omitempty"`
	Text     string `json:",omitempty"`
}

type Name struct {
	Text      string `json:",omitempty"`
	Operation string `json:",omitempty"`
}

type States struct {
	TextFileContent54State []TextFileContent54State `json:",omitempty"`
	RPMInfoStates          []RPMInfoState           `json:",omitempty"`
}

type Version struct {
	Text      string `json:",omitempty"`
	Operation string `json:",omitempty"`
}

type TextFileContent54State struct {
	ID      string `json:",omitempty"`
	Version string `json:",omitempty"`
	Text    Text   `json:",omitempty"`
}

type Text struct {
	Text      string `json:",omitempty"`
	Operation string `json:",omitempty"`
}

type pkg struct {
	Name         string
	FixedVersion string
	Arches       []string
}

type bucket struct {
	packageName     string
	vulnerabilityID string
}

type AdvisorySpecial struct {
	Entries []Entry `json:",omitempty"`
}

type DefinitionSpecial struct {
	Entry Entry `json:",omitempty"`
}

type Entry struct {
	FixedVersion string `json:",omitempty"`
	CVEs         []CVEEntry
	Arches       []string `json:",omitempty"`

	AffectedCPEList []string `json:",omitempty"`
}

type CVEEntry struct {
	ID string `json:",omitempty"`

	Severity types.Severity `json:",omitempty"`
}

type VendorCVE struct {
	Title       string
	Description string
	References  []string
	CVE         CVEEntry
}
