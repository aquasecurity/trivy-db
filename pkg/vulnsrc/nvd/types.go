package nvd

type Cve struct {
	ID               string          `json:"id"`
	SourceIdentifier string          `json:"sourceIdentifier"`
	Published        string          `json:"published"`
	LastModified     string          `json:"lastModified"`
	VulnStatus       string          `json:"vulnStatus"`
	Descriptions     []Description   `json:"descriptions"`
	Metrics          Metrics         `json:"metrics"`
	Weaknesses       []Weakness      `json:"weaknesses"`
	Configurations   []Configuration `json:"configurations"`
	References       []Reference     `json:"references"`
}

type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Metrics struct {
	CvssMetricV31 []CvssMetricV31 `json:"cvssMetricV31"`
	CvssMetricV2  []CvssMetricV2  `json:"cvssMetricV2"`
}

type CvssMetricV31 struct {
	Source              string   `json:"source"`
	Type                string   `json:"type"`
	CvssData            CvssData `json:"cvssData"`
	ExploitabilityScore float64  `json:"exploitabilityScore"`
	ImpactScore         float64  `json:"impactScore"`
}

type CvssMetricV2 struct {
	Source                  string   `json:"source"`
	Type                    string   `json:"type"`
	CvssData                CvssData `json:"cvssData"`
	BaseSeverity            string   `json:"baseSeverity"`
	ExploitabilityScore     float64  `json:"exploitabilityScore"`
	ImpactScore             float64  `json:"impactScore"`
	AcInsufInfo             bool     `json:"acInsufInfo"`
	ObtainAllPrivilege      bool     `json:"obtainAllPrivilege"`
	ObtainUserPrivilege     bool     `json:"obtainUserPrivilege"`
	ObtainOtherPrivilege    bool     `json:"obtainOtherPrivilege"`
	UserInteractionRequired bool     `json:"userInteractionRequired"`
}

type CvssData struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	AttackVector          string  `json:"attackVector"`
	AttackComplexity      string  `json:"attackComplexity"`
	PrivilegesRequired    string  `json:"privilegesRequired"`
	UserInteraction       string  `json:"userInteraction"`
	Scope                 string  `json:"scope"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseScore             float64 `json:"baseScore"`
	BaseSeverity          string  `json:"baseSeverity"`
}

type Weakness struct {
	Source      string        `json:"source"`
	Type        string        `json:"type"`
	Description []Description `json:"description"`
}

type Configuration struct {
	Nodes []Node `json:"nodes"`
}

type Node struct {
	Operator string     `json:"operator"`
	Negate   bool       `json:"negate"`
	CpeMatch []CpeMatch `json:"cpeMatch"`
}
type CpeMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
	MatchCriteriaID       string `json:"matchCriteriaId"`
	VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
}

type Reference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
}
