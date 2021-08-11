package nvd

import (
	"github.com/aquasecurity/trivy-db/pkg/types"
)

type NVD struct {
	CVEItems []Item `json:"CVE_Items"`
}

type Item struct {
	Configurations   Configurations
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

type Configurations struct {
	CveDataVersion string `json:"CVE_data_version"`
	Nodes          []Node `json:"nodes,omitempty"`
}

type Node struct {
	Children            []Node `json:"children,omitempty"`
	Operator            string `json:"operator,omitempty"`
	CPEMatch            []Node `json:"cpe_match,omitempty"`
	Cpe23Uri            string `json:"cpe23Uri,omitempty"`
	VersionEndExcluding string `json:"versionEndExcluding,omitempty"`
	Vulnerable          *bool  `json:"vulnerable,omitempty"`
}

func mapConfigurationsToCPEDetails(configuration Configurations, cpeDetail *types.CPEDetails) {
	cpeDetail.CveDataVersion = configuration.CveDataVersion
	if configuration.Nodes != nil {
		for _, n := range configuration.Nodes {
			var cpeNode types.Node
			mapConfigNodeToCPENode(n, &cpeNode)
			cpeDetail.Nodes = append(cpeDetail.Nodes, cpeNode)
		}
	}
}

func mapConfigNodeToCPENode(configNode Node, cpeNode *types.Node) {
	if configNode.Operator != "" {
		cpeNode.Operator = configNode.Operator
	}
	if configNode.Cpe23Uri != "" {
		cpeNode.Cpe23Uri = configNode.Cpe23Uri
	}
	if configNode.VersionEndExcluding != "" {
		cpeNode.VersionEndExcluding = configNode.VersionEndExcluding
	}
	if configNode.Vulnerable != nil {
		cpeNode.Vulnerable = configNode.Vulnerable
	}
	if configNode.Children != nil {
		for _, n := range configNode.Children {
			var cpeChildNode types.Node
			mapConfigNodeToCPENode(n, &cpeChildNode)
			cpeNode.Children = append(cpeNode.Children, cpeChildNode)
		}
	}
	if configNode.CPEMatch != nil {
		for _, n := range configNode.CPEMatch {
			var cpeMatchNode types.Node
			mapConfigNodeToCPENode(n, &cpeMatchNode)
			cpeNode.CPEMatch = append(cpeNode.CPEMatch, cpeMatchNode)
		}
	}
}

func boolptr(val bool) *bool {
	return &val
}
