package utils

import (
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/samber/oops"

	"github.com/aquasecurity/trivy-db/pkg/log"
)

func FileWalk(root string, walkFn func(r io.Reader, path string) error) error {
	eb := oops.With("root_dir", root)

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		eb := eb.With("path", path)
		if err != nil {
			return eb.Wrapf(err, "walk dir error")
		} else if d.IsDir() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return eb.Wrapf(err, "file info error")
		}

		if info.Size() == 0 {
			log.Info("Invalid file size", log.FilePath(path), log.Int64("size", info.Size()))
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return eb.Wrapf(err, "file open error")
		}
		defer f.Close()

		if err = walkFn(f, path); err != nil {
			return eb.Wrapf(err, "walk error")
		}
		return nil
	})
	if err != nil {
		return eb.Wrapf(err, "file walk error")
	}
	return nil
}

func Exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

func UnmarshalJSONFile(v interface{}, fileName string) error {
	eb := oops.With("file_name", fileName)

	f, err := os.Open(fileName)
	if err != nil {
		return eb.Wrapf(err, "file open error")
	}
	defer f.Close()

	if err = json.NewDecoder(f).Decode(v); err != nil {
		return eb.Wrapf(err, "json decode error")
	}
	return nil
}
