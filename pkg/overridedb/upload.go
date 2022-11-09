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
	result := &OverriddenData{}
	if err := yaml.NewDecoder(f).Decode(result); err != nil {
		log.Printf("override db: can't decode data from %q: %v", filename, err)
		return nil
	}
	return result
}
