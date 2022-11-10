package overridedb

import (
	"log"
	"os"

	"gopkg.in/yaml.v2"
)

func UploadOverriddenDB(filename string) *OverriddenData {
	f, err := os.Open(filename)
	if err != nil {
		log.Printf("override db: can't open %q: %v", filename, err)
		return nil
	}
	defer f.Close()
	overriddenAdvs := []OverriddenAdvisory{}
	if err := yaml.NewDecoder(f).Decode(&overriddenAdvs); err != nil {
		log.Printf("override db: can't decode data from %q: %v", filename, err)
		return nil
	}
	result := &OverriddenData{
		advisories: map[string]*OverriddenAdvisory{},
		aliases:    map[string]string{},
	}
	for _, adv := range overriddenAdvs {
		result.advisories[adv.Id] = &adv
		for _, alias := range adv.Aliases {
			result.aliases[alias] = adv.Id
		}
	}
	return result
}
