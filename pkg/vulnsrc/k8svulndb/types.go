package k8svulndb

type K8sCVE struct {
	ID              string    `json:"id,omitempty"`
	CreatedAt       string    `json:"created_at,omitempty"`
	Summary         string    `json:"summary,omitempty"`
	Component       string    `json:"component,omitempty"`
	Description     string    `json:"description,omitempty"`
	AffectedVersion []Version `json:"affected_version,omitempty"`
	FixedVersion    []Version `json:"fixed_version,omitempty"`
	Urls            []string  `json:"urls,omitempty"`
	Cvss            string    `json:"cvss,omitempty"`
	Severity        string    `json:"severity,omitempty"`
	Score           float64   `json:"score,omitempty"`
}

type Version struct {
	From  string `json:"from,omitempty"`
	To    string `json:"to,omitempty"`
	Fixed string `json:"fixed,omitempty"`
}
