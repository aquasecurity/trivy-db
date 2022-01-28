package pkg

import (
	"github.com/urfave/cli"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/vulndb"
)

func build(c *cli.Context) error {
	cacheDir := c.String("cache-dir")
	if err := db.Init(cacheDir); err != nil {
		return xerrors.Errorf("db initialize error: %w", err)
	}

	targets := c.StringSlice("only-update")
	updateInterval := c.Duration("update-interval")

	vdb := vulndb.New(cacheDir, updateInterval)
	if err := vdb.Build(targets); err != nil {
		return xerrors.Errorf("build error: %w", err)
	}

	return nil

}
