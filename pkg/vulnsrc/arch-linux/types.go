package archlinux

type ArchVulnGroup struct {
	Name       string   `json:"name"`
	Packages   []string `json:"packages"`
	Status     string   `json:"status"`
	Severity   string   `json:"severity"`
	Type       string   `json:"type"`
	Affected   string   `json:"affected"`
	Fixed      string   `json:"fixed"`
	Issues     []string `json:"issues"`
	Advisories []string `json:"advisories"`
}
