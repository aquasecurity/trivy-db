package pkg

import (
	"context"
	"io/ioutil"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/urfave/cli"
)

func (ac AppConfig) upload(c *cli.Context) error {
	dir := c.String("dir")
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return xerrors.Errorf("unable to list files: %w", err)
	}

	// only gz and tgz files
	var filePaths []string
	for _, f := range files {
		if f.IsDir() || (!strings.HasSuffix(f.Name(), "db.gz") && !strings.HasSuffix(f.Name(), "db.tgz")) {
			continue
		}
		path := filepath.Join(dir, f.Name())
		filePaths = append(filePaths, path)
	}

	ctx := context.Background()
	if err := ac.Client.UploadReleaseAssets(ctx, filePaths); err != nil {
		return xerrors.Errorf("failed to upload a release asset: %w", err)
	}
	return nil
}
