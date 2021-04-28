package glad

type Advisory struct {
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
