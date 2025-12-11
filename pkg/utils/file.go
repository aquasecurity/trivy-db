package utils

import (
	"bytes"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/samber/oops"

	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/override"
)

var patches *override.Patches

// SetOverrides sets the override patches to be applied during FileWalk.
// This should be called before any FileWalk calls.
func SetOverrides(p *override.Patches) {
	patches = p
	if p != nil {
		log.Info("Loaded override patches", log.Int("count", p.Count()))
	}
}

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

		var r io.Reader = f

		// Apply patch if matching path suffix
		if patch, ok, err := patches.Match(path); err != nil {
			return eb.Wrapf(err, "patch match error")
		} else if ok {
			content, err := io.ReadAll(f)
			if err != nil {
				return eb.Wrapf(err, "file read error")
			}

			patched, err := patch.Apply(content)
			if err != nil {
				return eb.Wrapf(err, "patch apply error")
			}

			if len(patched) == 0 {
				log.Debug("Skipping file due to override", log.FilePath(path))
				return nil
			}

			r = bytes.NewReader(patched)
			log.Debug("Applied override patch", log.FilePath(path))
		}

		if err = walkFn(r, path); err != nil {
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

func UnmarshalJSONFile(v any, fileName string) error {
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
