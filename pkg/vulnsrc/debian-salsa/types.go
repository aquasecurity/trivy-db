package debian

type DebianCVE struct {
	Description     string             `json:"description,omitempty"`
	Releases        map[string]Release `json:"releases,omitempty"`
	Package         string
	VulnerabilityID string
}

type Release struct {
	FixVersion             string                            `json:"fix_version"`
	WillNotFix             bool                              `json:"will_not_fix"`
	Severity               string                            `json:"severity"`
	Statement              string                            `json:"statement"`
	SecurityAdvisory       map[string]SecurityAdvisoryDebian `json:"security_advisory"`
	ClassificationID       int64                             `json:"classification_id"`
	SeverityClassification string                            `json:"severity_classification"`
}

type SecurityAdvisoryDebian struct {
	SecurityAdvisoryId string `json:"security_advisory_id,omitempty"`
	Severity           string `json:"severity,omitempty"`
	PublishDate        string `json:"publish_date,omitempty"`
	Description        string `json:"description,omitempty"`
}
