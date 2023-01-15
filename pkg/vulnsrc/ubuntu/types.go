package ubuntu

type UbuntuCVE struct {
	Description string `json:"description"`
	Candidate   string
	Priority    string
	Patches     map[PackageName]Patch
	References  []string
	PublicDate  string // for extensibility, not used in trivy-db
}

type PackageName string
type Release string
type Patch map[Release]Status

type Status struct {
	Status string
	Note   string
}
