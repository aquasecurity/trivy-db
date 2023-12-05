package nvd

// Cve is based on https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema (see `cve_item`)
type Cve struct {
	ID                string          `json:"id"`
	SourceIdentifier  string          `json:"sourceIdentifier,omitempty"`
	Published         string          `json:"published"`
	LastModified      string          `json:"lastModified"`
	VulnStatus        string          `json:"vulnStatus,omitempty"`
	EvaluatorComment  string          `json:"evaluatorComment,omitempty"`
	EvaluatorSolution string          `json:"evaluatorSolution,omitempty"`
	EvaluatorImpact   string          `json:"evaluatorImpact,omitempty"`
	CisaExploitAdd    string          `json:"cisaExploitAdd,omitempty"`
	CisaActionDue     string          `json:"cisaActionDue,omitempty"`
	Descriptions      []LangString    `json:"descriptions"`
	Metrics           Metrics         `json:"metrics,omitempty"`
	Weaknesses        []Weakness      `json:"weaknesses,omitempty"`
	Configurations    []Configuration `json:"configurations,omitempty"`
	References        []Reference     `json:"references"`
	VendorComments    []VendorComment `json:"vendorComments,omitempty"`
}

type LangString struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Reference struct {
	URL    string   `json:"url"`
	Source string   `json:"source,omitempty"`
	Tags   []string `json:"tags,omitempty"`
}

type Metrics struct {
	CvssMetricV31 []CvssMetricV3 `json:"cvssMetricV31,omitempty"`
	CvssMetricV30 []CvssMetricV3 `json:"cvssMetricV30,omitempty"`
	CvssMetricV2  []CvssMetricV2 `json:"cvssMetricV2,omitempty"`
}

// CvssMetricV3 is based on https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema.
// v3.0 and v3.1 have only one difference: `cvssData`.
// But we can use `cvssData` v3.0 for v3.1 (see below).
// So we can use the same structure for v3.0 and v3.1.
type CvssMetricV3 struct {
	Source              string      `json:"source"`
	Type                string      `json:"type"`
	CvssData            CvssDataV30 `json:"cvssData"`
	ExploitabilityScore float64     `json:"exploitabilityScore,omitempty"`
	ImpactScore         float64     `json:"impactScore,omitempty"`
}

// CvssDataV30 is based on https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v3.0.json
// v3.0 and v3.1 have only one difference: `patterns` for `vectorString`.
// So we can use version 3.0 for version 3.1.
type CvssDataV30 struct {
	Version                       string  `json:"version"`
	VectorString                  string  `json:"vectorString"`
	AttackVector                  string  `json:"attackVector,omitempty"`
	AttackComplexity              string  `json:"attackComplexity,omitempty"`
	PrivilegesRequired            string  `json:"privilegesRequired,omitempty"`
	UserInteraction               string  `json:"userInteraction,omitempty"`
	Scope                         string  `json:"scope,omitempty"`
	ConfidentialityImpact         string  `json:"confidentialityImpact,omitempty"`
	IntegrityImpact               string  `json:"integrityImpact,omitempty"`
	AvailabilityImpact            string  `json:"availabilityImpact,omitempty"`
	BaseScore                     float64 `json:"baseScore"`
	BaseSeverity                  string  `json:"baseSeverity"`
	ExploitCodeMaturity           string  `json:"exploitCodeMaturity,omitempty"`
	RemediationLevel              string  `json:"remediationLevel,omitempty"`
	ReportConfidence              string  `json:"reportConfidence,omitempty"`
	TemporalScore                 float64 `json:"temporalScore,omitempty"`
	TemporalSeverity              string  `json:"temporalSeverity,omitempty"`
	ConfidentialityRequirement    string  `json:"confidentialityRequirement,omitempty"`
	IntegrityRequirement          string  `json:"integrityRequirement,omitempty"`
	AvailabilityRequirement       string  `json:"availabilityRequirement,omitempty"`
	ModifiedAttackVector          string  `json:"modifiedAttackVector,omitempty"`
	ModifiedAttackComplexity      string  `json:"modifiedAttackComplexity,omitempty"`
	ModifiedPrivilegesRequired    string  `json:"modifiedPrivilegesRequired,omitempty"`
	ModifiedUserInteraction       string  `json:"modifiedUserInteraction,omitempty"`
	ModifiedScope                 string  `json:"modifiedScope,omitempty"`
	ModifiedConfidentialityImpact string  `json:"modifiedConfidentialityImpact,omitempty"`
	ModifiedIntegrityImpact       string  `json:"modifiedIntegrityImpact,omitempty"`
	ModifiedAvailabilityImpact    string  `json:"modifiedAvailabilityImpact,omitempty"`
	EnvironmentalScore            float64 `json:"environmentalScore,omitempty"`
	EnvironmentalSeverity         string  `json:"environmentalSeverity,omitempty"`
}

type CvssMetricV2 struct {
	Source                  string      `json:"source"`
	Type                    string      `json:"type"`
	CvssData                CvssDataV20 `json:"cvssData"`
	BaseSeverity            string      `json:"baseSeverity,omitempty"`
	ExploitabilityScore     float64     `json:"exploitabilityScore,omitempty"`
	ImpactScore             float64     `json:"impactScore,omitempty"`
	AcInsufInfo             bool        `json:"acInsufInfo"`
	ObtainAllPrivilege      bool        `json:"obtainAllPrivilege"`
	ObtainUserPrivilege     bool        `json:"obtainUserPrivilege"`
	ObtainOtherPrivilege    bool        `json:"obtainOtherPrivilege"`
	UserInteractionRequired bool        `json:"userInteractionRequired"`
}

// CvssDataV20 is based on https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v2.0.json
type CvssDataV20 struct {
	Version                    string  `json:"version"`
	VectorString               string  `json:"vectorString"`
	AccessVector               string  `json:"accessVector,omitempty"`
	AccessComplexity           string  `json:"accessComplexity,omitempty"`
	Authentication             string  `json:"authentication,omitempty"`
	ConfidentialityImpact      string  `json:"confidentialityImpact,omitempty"`
	IntegrityImpact            string  `json:"integrityImpact,omitempty"`
	AvailabilityImpact         string  `json:"availabilityImpact,omitempty"`
	BaseScore                  float64 `json:"baseScore"`
	Exploitability             string  `json:"exploitability,omitempty"`
	RemediationLevel           string  `json:"remediationLevel,omitempty"`
	ReportConfidence           string  `json:"reportConfidence,omitempty"`
	TemporalScore              float64 `json:"temporalScore,omitempty"`
	CollateralDamagePotential  string  `json:"collateralDamagePotential,omitempty"`
	TargetDistribution         string  `json:"targetDistribution,omitempty"`
	ConfidentialityRequirement string  `json:"confidentialityRequirement,omitempty"`
	IntegrityRequirement       string  `json:"integrityRequirement,omitempty"`
	AvailabilityRequirement    string  `json:"availabilityRequirement,omitempty"`
	EnvironmentalScore         float64 `json:"environmentalScore,omitempty"`
}

type Weakness struct {
	Source      string       `json:"source"`
	Type        string       `json:"type"`
	Description []LangString `json:"description"`
}

type Configuration struct {
	Operator string `json:"operator,omitempty"`
	Negate   bool   `json:"negate,omitempty"`
	Nodes    []Node `json:"nodes"`
}

type Node struct {
	Operator string     `json:"operator"`
	Negate   bool       `json:"negate"`
	CpeMatch []CpeMatch `json:"cpeMatch"`
}
type CpeMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	MatchCriteriaID       string `json:"matchCriteriaId"`
	VersionStartExcluding string `json:"versionStartExcluding,omitempty"`
	VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
	VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
	VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
}

type VendorComment struct {
	Organization string `json:"organization"`
	Comment      string `json:"comment"`
	LastModified string `json:"lastModified"`
}
