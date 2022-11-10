package overridedb

type OverriddenData struct {
	aliases    map[string]string
	advisories map[string]*OverriddenAdvisory
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

func (db *OverriddenData) GetOverriddenAdvisory(vulnId string) *OverriddenAdvisory {
	if adv, ok := db.advisories[vulnId]; ok {
		return adv
	}
	if alias, ok := db.aliases[vulnId]; ok {
		return db.advisories[alias]
	}
	return nil
}
