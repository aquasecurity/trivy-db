package nvd

type NVD struct {
	CVEItems []Item `json:"CVE_Items"`
}

type Item struct {
	Cve              Cve
	Impact           Impact
	LastModifiedDate string `json:"lastModifiedDate"`
	PublishedDate    string `json:"publishedDate"`
}

type Cve struct {
	Meta        Meta `json:"CVE_data_meta"`
	References  References
	Description Description
	ProblemType ProblemType
}

type Meta struct {
	ID string
}

type Impact struct {
	BaseMetricV2 BaseMetricV2
	BaseMetricV3 BaseMetricV3
}

type BaseMetricV2 struct {
	CvssV2   CvssV2
	Severity string
}

type CvssV2 struct {
	BaseScore    float64 `json:"baseScore"`
	VectorString string  `json:"vectorString"`
}

type BaseMetricV3 struct {
	CvssV3 CvssV3
}

type CvssV3 struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string
	VectorString string `json:"vectorString"`
}

type References struct {
	ReferenceDataList []ReferenceData `json:"reference_data"`
}
type ReferenceData struct {
	Name      string
	Refsource string
	URL       string
}

type Description struct {
	DescriptionDataList []DescriptionData `json:"description_data"`
}

type DescriptionData struct {
	Lang  string
	Value string
}

type ProblemType struct {
	ProblemTypeData []ProblemTypeData `json:"problemtype_data"`
}

type ProblemTypeData struct {
	Description []ProblemTypeDataDescription
}

type ProblemTypeDataDescription struct {
	Lang  string
	Value string
}
