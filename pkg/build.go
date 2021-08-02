package pkg

import (
	"github.com/urfave/cli"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	trivydb "github.com/aquasecurity/trivy-db/pkg/trivy-db"
)

func build(c *cli.Context) error {
	cacheDir := c.String("cache-dir")
	if err := db.Init(cacheDir); err != nil {
		return err
	}

	targets := c.StringSlice("only-update")
	light := c.Bool("light")
	updateInterval := c.Duration("update-interval")

	dbType := db.TypeFull
	if light {
		dbType = db.TypeLight
	}

	tdb := trivydb.New(dbType, cacheDir, updateInterval)
	if err := tdb.Build(targets); err != nil {
		return xerrors.Errorf("build error: %w", err)
	}

	return nil

}
