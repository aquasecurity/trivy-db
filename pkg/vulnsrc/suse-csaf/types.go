package susecsaf

type SuseCvrf struct {
	Title           string
	Tracking        DocumentTracking
	Notes           []DocumentNote
	ProductTree     ProductTree
	References      []Reference
	Vulnerabilities []Vulnerability
}

type DocumentTracking struct {
	ID string
}

type DocumentNote struct {
	Text  string
	Title string
	Type  string
}

type ProductTree struct {
	Relationships []Relationship
}

type Relationship struct {
	ProductReference          string
	RelatesToProductReference string
}

type Vulnerability struct {
	Threats []Threat
}

type Threat struct {
	Type     string
	Severity string
}

type Reference struct {
	URL string
}

type Package struct {
	Name         string
	FixedVersion string
}

type AffectedPackage struct {
	Package Package
	OSVer   string
}

type SuseCSAF struct {
	Document        CSAFDocument        `json:"document"`
	ProductTree     CSAFProductTree     `json:"product_tree"`
	Vulnerabilities []CSAFVulnerability `json:"vulnerabilities"`
}

type CSAFDocument struct {
	Title      string          `json:"title"`
	Tracking   CSAFTracking    `json:"tracking"`
	Notes      []CSAFNote      `json:"notes"`
	References []CSAFReference `json:"references"`
}

type CSAFTracking struct {
	ID string `json:"id"`
}

type CSAFNote struct {
	Category string `json:"category"`
	Text     string `json:"text"`
	Title    string `json:"title"`
}

type CSAFReference struct {
	URL string `json:"url"`
}

type CSAFProductTree struct {
	Relationships []CSAFRelationship `json:"relationships"`
}

type CSAFRelationship struct {
	ProductReference          string `json:"product_reference"`
	RelatesToProductReference string `json:"relates_to_product_reference"`
}

type CSAFVulnerability struct {
	Threats []CSAFThreat `json:"threats"`
}

type CSAFThreat struct {
	Category string `json:"category"`
	Details  string `json:"details"`
}
