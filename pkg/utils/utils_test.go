package utils

import (
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
