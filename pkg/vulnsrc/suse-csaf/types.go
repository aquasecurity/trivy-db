package susecsaf

type Advisory struct {
	ID              string
	Title           string
	Notes           []Note
	ProductTree     ProductTree
	References      []Reference
	Vulnerabilities []Vulnerability
}

type Note struct {
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

type rawAdvisory struct {
	Document        rawDocument        `json:"document"`
	ProductTree     rawProductTree     `json:"product_tree"`
	Vulnerabilities []rawVulnerability `json:"vulnerabilities"`
}

type rawDocument struct {
	Title      string         `json:"title"`
	Tracking   rawTracking    `json:"tracking"`
	Notes      []rawNote      `json:"notes"`
	References []rawReference `json:"references"`
}

type rawTracking struct {
	ID string `json:"id"`
}

type rawNote struct {
	Category string `json:"category"`
	Text     string `json:"text"`
	Title    string `json:"title"`
}

type rawReference struct {
	URL string `json:"url"`
}

type rawProductTree struct {
	Relationships []rawRelationship `json:"relationships"`
}

type rawRelationship struct {
	ProductReference          string `json:"product_reference"`
	RelatesToProductReference string `json:"relates_to_product_reference"`
}

type rawVulnerability struct {
	Threats []rawThreat `json:"threats"`
}

type rawThreat struct {
	Category string `json:"category"`
	Details  string `json:"details"`
}
