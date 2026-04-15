package rootio

// OSVAdvisory is a subset of OSV schema v1.6.0 used by the rootio source.
type OSVAdvisory struct {
	ID               string        `json:"id"`
	Upstream         []string      `json:"upstream"`
	Affected         []OSVAffected `json:"affected"`
	DatabaseSpecific struct {
		Distro        string `json:"distro"`
		DistroVersion string `json:"distro_version"`
	} `json:"database_specific"`
}

type OSVAffected struct {
	Package OSVPackage `json:"package"`
	Ranges  []OSVRange `json:"ranges"`
}

type OSVPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type OSVRange struct {
	Events []OSVEvent `json:"events"`
}

type OSVEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}
