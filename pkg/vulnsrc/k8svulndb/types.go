package k8svulndb

type K8sCVE struct {
	ID               string     `json:"id,omitempty"`
	CreatedAt        string     `json:"created_at,omitempty"`
	Summary          string     `json:"summary,omitempty"`
	Component        string     `json:"component,omitempty"`
	Description      string     `json:"description,omitempty"`
	AffectedVersions []*Version `json:"affected_versions,omitempty"`
	FixedVersion     []*Version `json:"-"`
	Urls             []string   `json:"urls,omitempty"`
	CvssV3           Cvssv3     `json:"cvssv3,omitempty"`
	Severity         string     `json:"severity,omitempty"`
}

type Version struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

type Cvssv3 struct {
	Vector string
	Score  float64
}
