package pkg

import (
	"context"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/urfave/cli"
)

func (ac AppConfig) upload(c *cli.Context) error {
	dir := c.String("dir")
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return err
	}

	// only gz file
	var filePaths []string
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), "db.gz") {
			continue
		}
		path := filepath.Join(dir, f.Name())
		filePaths = append(filePaths, path)
	}

	ctx := context.Background()
	if err := ac.Client.UploadReleaseAsset(ctx, filePaths); err != nil {
		return err
	}
	return nil
}
