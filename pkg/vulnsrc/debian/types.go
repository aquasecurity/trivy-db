package debian

import "github.com/aquasecurity/trivy-db/pkg/types"

type header struct {
	VulnerabilityID string `json:"ID"`
	Description     string `json:"Description"`
}

type annotation struct {
	Type        string   `json:"Type"`
	Release     string   `json:"Release,omitempty"`
	Package     string   `json:"Package"`
	State       string   `json:"Kind"`
	Version     string   `json:"Version"`
	Description string   `json:"Description,omitempty"`
	Severity    string   `json:"Severity,omitempty"`
	Bugs        []string `json:"Bugs"`
}

type DebianSrcCVE struct {
	Header      header       `json:"Header"`
	Annotations []annotation `json:"Annotations"`
}

type VulnDetail struct {
	FixedVersion string         `json:"FixedVersion"`
	VendorIds    []string       `json:"VendorIDs,omitempty"`
	State        string         `json:"State,omitempty"`
	Description  string         `json:"Description,omitempty"`
	Severity     types.Severity `json:"Severity,omitempty"`
}
