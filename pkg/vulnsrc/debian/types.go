package debian

import "github.com/aquasecurity/trivy-db/pkg/types"

type bucket struct {
	codeName string
	pkgName  string
	vulnID   string // CVE-ID, DLA-ID or DSA-ID
	severity types.Severity
}

type header struct {
	ID          string `json:"ID"`
	Description string `json:"Description"`
}

type annotation struct {
	Type        string
	Release     string
	Package     string
	Kind        string
	Version     string
	Description string
	Severity    string
	Bugs        []string
}

type Bug struct {
	Header      header
	Annotations []annotation
}
