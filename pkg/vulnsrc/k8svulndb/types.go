package k8svulndb

type K8sCVE struct {
	ID         string      `json:"id,omitempty"`
	CreatedAt  string      `json:"created_at,omitempty"`
	Summary    string      `json:"summary,omitempty"`
	Component  string      `json:"component,omitempty"`
	Details    string      `json:"details,omitempty"`
	Affected   []*Affected `json:"affected,omitempty"`
	References []string    `json:"references,omitempty"`
	CvssV3     Cvssv3      `json:"cvssv3,omitempty"`
	Severity   string      `json:"severity,omitempty"`
}

type Cvssv3 struct {
	Vector string
	Score  float64
}

type Version struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
	FixedIndex   int    `json:"-"`
}

type Affected struct {
	Ranges []*Range `json:"ranges,omitempty"`
}

type Range struct {
	Events    []*Event `json:"events,omitempty"`
	RangeType string   `json:"type,omitempty"`
}

type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}
