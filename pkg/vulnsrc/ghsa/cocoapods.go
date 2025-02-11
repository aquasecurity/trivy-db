package ghsa

import (
	"encoding/json"
	"io"
	"path/filepath"

	"github.com/samber/oops"
	"golang.org/x/exp/slices"

	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

// Spec is cocoapods struct
type Spec struct {
	Name   string `json:"name"`
	Source Source `json:"source"`
}

type Source struct {
	Git string `json:"git"`
}

var cocoapodsSpecDir = filepath.Join("cocoapods-specs", "Specs")

func walkCocoaPodsSpecs(root string) (map[string][]string, error) {
	log.WithPrefix("cocoapods").Info("Walk `Cocoapods Specs` to convert Swift URLs to Cocoapods package names")
	eb := oops.In("cocoapods").With("root_dir", root)

	var specs = make(map[string][]string)
	err := utils.FileWalk(filepath.Join(root, cocoapodsSpecDir), func(r io.Reader, path string) error {
		if filepath.Ext(path) != ".json" {
			return nil
		}
		var spec Spec
		if err := json.NewDecoder(r).Decode(&spec); err != nil {
			return eb.With("file_path", path).Wrapf(err, "json decode error")
		}
		if spec.Source.Git == "" {
			return nil
		}

		// Trim `https://` prefix and `.git` suffix to fit the format
		link := vulnerability.NormalizePkgName(vulnerability.Swift, spec.Source.Git)
		// some packages (or subpackages) can use same git url
		// we need to save all packages
		if names, ok := specs[link]; ok {
			if !slices.Contains(names, spec.Name) {
				specs[link] = append(specs[link], spec.Name)
			}
		} else {
			specs[link] = []string{spec.Name}
		}
		return nil
	})
	if err != nil {
		return nil, eb.Wrapf(err, "walk error")
	}
	return specs, nil
}
