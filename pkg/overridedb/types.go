package overridedb

type OverriddenData struct {
	Aliases    map[string]string
	Advisories map[string]OverriddenAdvisory
}

type OverriddenAdvisory struct {
	Id               string   `yaml:"id"`
	Description      string   `yaml:"description"`
	Aliases          []string `yaml:"aliases"`
	Severity         string   `yaml:"severity"`
	AffectedVersions []string `yaml:"affected"`
	FixedVersions    []string `yaml:"fixed"`

	wasAdded bool
}

func (a *OverriddenAdvisory) WasAdded() bool {
	return a.wasAdded
}
func (a *OverriddenAdvisory) SetAdded() {
	a.wasAdded = true
}
