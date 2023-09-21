package oval

// Definition is struct of `definitions.json` files
type Definition struct {
	Class    string
	ID       string
	Version  string
	Metadata Metadata
	Criteria Criteria
}

type Criteria struct {
	Operator  string
	Criterion Criterion
}

type Criterion struct {
	Comment string
	TestRef string
}

type Metadata struct {
	Title        string
	Affected     Affected
	Reference    Reference
	Patchable    string
	AdvisoryDate string
	AdvisoryID   string
	Severity     string
	Description  string
}

type Reference struct {
	RefID  string
	RefURL string
	Source string
}

type Affected struct {
	Family   string
	Platform string
}

type State struct {
	StateRef string
}

type Object struct {
	ObjectRef string
}

// Tests is struct of `tests.json` files
type Tests struct {
	RpminfoTests []RpmInfoTest
}

type RpmInfoTest struct {
	Check   string
	Comment string
	ID      string
	Version string
	Object  Object
	State   State
}

// Objects is struct of `objects.json` files
type Objects struct {
	RpminfoObjects []RpmInfoObject
}

type RpmInfoObject struct {
	ID      string
	Version string
	Name    string
}

// States is struct of `states.json` files
type States struct {
	RpminfoState []RpmInfoState
}

type RpmInfoState struct {
	ID      string
	Version string
	Evr     Evr
}

type Evr struct {
	Text      string
	Datatype  string
	Operation string
}
