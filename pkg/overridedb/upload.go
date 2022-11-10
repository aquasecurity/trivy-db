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
		Advisories: map[string]OverriddenAdvisory{},
		Aliases:    map[string]string{},
	}
	for _, adv := range overriddenAdvs {
		result.Advisories[adv.Id] = adv
		for _, alias := range adv.Aliases {
			result.Aliases[alias] = adv.Id
		}
	}
	return result
}
