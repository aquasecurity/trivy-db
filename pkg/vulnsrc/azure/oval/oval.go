package oval

import (
	"encoding/json"
	"io"
	"path/filepath"

	"github.com/samber/oops"

	"github.com/aquasecurity/trivy-db/pkg/utils"
)

func ParseDefinitions(dir string) ([]Definition, error) {
	dir = filepath.Join(dir, "definitions")
	eb := oops.In("azure").Tags("oval").With("dir", dir)

	if exists, _ := utils.Exists(dir); !exists {
		return nil, eb.Errorf("no definitions dir")
	}

	var defs []Definition

	err := utils.FileWalk(dir, func(r io.Reader, path string) error {
		var def Definition
		if err := json.NewDecoder(r).Decode(&def); err != nil {
			return eb.With("file_path", path).Wrapf(err, "failed to decode")
		}
		defs = append(defs, def)
		return nil
	})
	if err != nil {
		return nil, eb.Wrapf(err, "walk error")
	}

	return defs, nil
}

func ParseTests(dir string) (Tests, error) {
	eb := oops.In("azure").Tags("oval").With("dir", dir)
	var tests Tests
	if err := utils.UnmarshalJSONFile(&tests, filepath.Join(dir, "tests", "tests.json")); err != nil {
		return tests, eb.Wrapf(err, "json unmarshal error")
	}
	return tests, nil
}

func ParseObjects(dir string) (map[string]string, error) {
	eb := oops.In("azure").Tags("oval").With("dir", dir)
	var objects Objects
	if err := utils.UnmarshalJSONFile(&objects, filepath.Join(dir, "objects", "objects.json")); err != nil {
		return nil, eb.Wrapf(err, "json unmarshal error")
	}
	objs := map[string]string{}
	for _, obj := range objects.RpminfoObjects {
		objs[obj.ID] = obj.Name
	}
	return objs, nil
}

func ParseStates(dir string) (map[string]RpmInfoState, error) {
	eb := oops.In("azure").Tags("oval").With("dir", dir)
	var ss States
	if err := utils.UnmarshalJSONFile(&ss, filepath.Join(dir, "states", "states.json")); err != nil {
		return nil, eb.Wrapf(err, "json unmarshal error")
	}

	states := map[string]RpmInfoState{}
	for _, state := range ss.RpminfoState {
		states[state.ID] = state
	}
	return states, nil
}
