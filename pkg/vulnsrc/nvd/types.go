package nvd

// Cve is based on https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema (see `cve_item`)
type Cve struct {
	ID           string       `json:"id"`
	Published    string       `json:"published"`
	LastModified string       `json:"lastModified"`
	Descriptions []LangString `json:"descriptions"`
	Metrics      Metrics      `json:"metrics,omitempty"`
	Weaknesses   []Weakness   `json:"weaknesses,omitempty"`
	References   []Reference  `json:"references"`
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
	Source   string      `json:"source"`
	Type     string      `json:"type"`
	CvssData CvssDataV30 `json:"cvssData"`
}

// CvssDataV30 is based on https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v3.0.json
// v3.0 and v3.1 have only one difference: `patterns` for `vectorString`.
// So we can use version 3.0 for version 3.1.
type CvssDataV30 struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type CvssMetricV2 struct {
	Source       string      `json:"source"`
	Type         string      `json:"type"`
	CvssData     CvssDataV20 `json:"cvssData"`
	BaseSeverity string      `json:"baseSeverity,omitempty"`
}

// CvssDataV20 is based on https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v2.0.json
type CvssDataV20 struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
}

type Weakness struct {
	Source      string       `json:"source"`
	Type        string       `json:"type"`
	Description []LangString `json:"description"`
}
