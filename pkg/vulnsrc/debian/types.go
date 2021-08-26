package debian

type bucket struct {
	codeName string
	pkgName  string
	cveID    string
}

type header struct {
	ID          string `json:"ID"`
	Description string `json:"Description"`
}

type annotation struct {
	Type        string   `json:"Type"`
	Release     string   `json:"Release,omitempty"`
	Package     string   `json:"Package"`
	Kind        string   `json:"Kind"`
	Version     string   `json:"MajorVersion"`
	Description string   `json:"Description,omitempty"`
	Severity    string   `json:"Severity,omitempty"`
	Bugs        []string `json:"Bugs"`
}

type Bug struct {
	Header      header       `json:"Header"`
	Annotations []annotation `json:"Annotations"`
}
