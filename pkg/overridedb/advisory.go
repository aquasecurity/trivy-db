package overridedb

type OverriddenData []OverriddenAdvisory

type OverriddenAdvisory struct {
	Id          string   `yaml:"id"`
	Description string   `yaml:"description"`
	Aliases     []string `yaml:"aliases"`
	Severity    string   `yaml:"severity"`
	//affected ranges,
	//fixed version(s),
}
