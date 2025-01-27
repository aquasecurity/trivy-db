package redhatoval

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/samber/oops"
)

type rpmInfoTest struct {
	Name           string
	SignatureKeyID signatureKeyID
	FixedVersion   string
	Arch           string
}

func unmarshalJSONFile(v interface{}, fileName string) error {
	eb := oops.With("file_path", fileName)

	f, err := os.Open(fileName)
	if err != nil {
		return eb.Wrapf(err, "unable to open a file")
	}
	defer f.Close()

	if err = json.NewDecoder(f).Decode(v); err != nil {
		return eb.Wrapf(err, "json decode error")
	}
	return nil
}

func parseObjects(dir string) (map[string]string, error) {
	var objects ovalObjects
	if err := unmarshalJSONFile(&objects, filepath.Join(dir, "objects", "objects.json")); err != nil {
		return nil, oops.Wrapf(err, "failed to unmarshal objects")
	}
	objs := map[string]string{}
	for _, obj := range objects.RpminfoObjects {
		objs[obj.ID] = obj.Name
	}
	return objs, nil
}

func parseStates(dir string) (map[string]rpminfoState, error) {
	var ss ovalStates
	if err := unmarshalJSONFile(&ss, filepath.Join(dir, "states", "states.json")); err != nil {
		return nil, oops.Wrapf(err, "failed to unmarshal states")
	}

	states := map[string]rpminfoState{}
	for _, state := range ss.RpminfoState {
		states[state.ID] = state
	}
	return states, nil
}

func parseTests(dir string) (map[string]rpmInfoTest, error) {
	objects, err := parseObjects(dir)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to parse objects")
	}

	states, err := parseStates(dir)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to parse states")
	}

	var tt ovalTests
	if err := unmarshalJSONFile(&tt, filepath.Join(dir, "tests", "tests.json")); err != nil {
		return nil, oops.Wrapf(err, "failed to unmarshal states")
	}

	tests := map[string]rpmInfoTest{}
	for _, test := range tt.RpminfoTests {
		// test.Check should be "at least one"
		if test.Check != "at least one" {
			continue
		}

		t, err := followTestRefs(test, objects, states)
		if err != nil {
			return nil, oops.Wrapf(err, "unable to follow test refs")
		}
		tests[test.ID] = t
	}
	return tests, nil
}

func followTestRefs(test rpminfoTest, objects map[string]string, states map[string]rpminfoState) (rpmInfoTest, error) {
	var t rpmInfoTest
	eb := oops.With("object_ref", test.Object.ObjectRef).With("test_ref", test.ID).With("state_ref", test.State.StateRef)

	// Follow object ref
	if test.Object.ObjectRef == "" {
		return t, nil
	}

	pkgName, ok := objects[test.Object.ObjectRef]
	if !ok {
		return t, eb.Errorf("invalid tests data, can't find object ref")
	}
	t.Name = pkgName

	// Follow state ref
	if test.State.StateRef == "" {
		return t, nil
	}

	state, ok := states[test.State.StateRef]
	if !ok {
		return t, eb.Errorf("invalid tests data, can't find ovalstate ref")
	}

	t.SignatureKeyID = state.SignatureKeyID

	if state.Arch.Datatype == "string" && (state.Arch.Operation == "pattern match" || state.Arch.Operation == "equals") {
		t.Arch = state.Arch.Text
	}

	if state.Evr.Datatype == "evr_string" && state.Evr.Operation == "less than" {
		t.FixedVersion = state.Evr.Text
	}

	return t, nil
}
