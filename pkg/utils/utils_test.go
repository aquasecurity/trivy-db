package utils

import (
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func touch(t *testing.T, name string) {
	f, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func write(t *testing.T, name string, content string) {
	err := ioutil.WriteFile(name, []byte(content), 0666)
	if err != nil {
		t.Fatal(err)
	}
}

func TestFileWalk(t *testing.T) {
	td, err := ioutil.TempDir("", "walktest")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(td)

	if err := os.MkdirAll(filepath.Join(td, "dir"), 0755); err != nil {
		t.Fatal(err)
	}
	touch(t, filepath.Join(td, "dir/foo1"))
	touch(t, filepath.Join(td, "dir/foo2"))
	write(t, filepath.Join(td, "dir/foo3"), "foo3")

	sawDir := false
	sawFoo1 := false
	sawFoo2 := false
	var contentFoo3 []byte
	walker := func(r io.Reader, path string) error {
		if strings.HasSuffix(path, "dir") {
			sawDir = true
		}
		if strings.HasSuffix(path, "foo1") {
			sawFoo1 = true
		}
		if strings.HasSuffix(path, "foo2") {
			sawFoo2 = true
		}
		if strings.HasSuffix(path, "foo3") {
			contentFoo3, err = ioutil.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
		}
		return nil
	}

	err = FileWalk(td, walker)
	if err != nil {
		t.Fatal(err)
	}
	if sawDir {
		t.Error("directories must not be passed to walkFn")
	}
	if sawFoo1 || sawFoo2 {
		t.Error("an empty file must not be passed to walkFn")
	}
	if string(contentFoo3) != "foo3" {
		t.Error("The file content is wrong")
	}
}

func TestUniq(t *testing.T) {
	testCases := []struct {
		name       string
		inputData  []string
		expectData []string
	}{
		{

			name: "positive test",
			inputData: []string{
				"test string 1",
				"test string 3",
				"test string 2",
				"test string 1",
				"test string 2",
				"test string 3",
			},
			expectData: []string{
				"test string 1",
				"test string 2",
				"test string 3",
			},
		},
		{
			name:       "positive test input empty",
			inputData:  []string{},
			expectData: []string{},
		},
		{
			name: "positive test input uniq",
			inputData: []string{
				"test string 1",
				"test string 3",
				"test string 2",
			},
			expectData: []string{
				"test string 1",
				"test string 2",
				"test string 3",
			},
		},
	}
	for _, testCase := range testCases {
		actualData := Uniq(testCase.inputData)
		assert.Equal(t, actualData, testCase.expectData, testCase.name)
	}

}
