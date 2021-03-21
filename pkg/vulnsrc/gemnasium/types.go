package gemnasium

type Advisory struct {
	VulnerabilityID string   `json:",omitempty"`
	AffectedRange   string   `json:",omitempty"`
	PatchedVersions []string `json:",omitempty"`
}

type GemnasiumAdvisory struct {
	Identifier       string
	PackageSlug      string
	Title            string
	Description      string
	Date             string
	Pubdate          string
	AffectedRange    string
	FixedVersions    []string
	AffectedVersions string
	NotImpacted      string
	Solution         string
	Urls             []string
	CvssV2           string
	CvssV3           string
	UUID             string
}
