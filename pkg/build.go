package pkg

import (
	"github.com/samber/oops"
	"github.com/urfave/cli"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/vulndb"
)

func build(c *cli.Context) error {
	outputDir := c.String("output-dir")
	eb := oops.With("output_dir", outputDir)

	if err := db.Init(outputDir); err != nil {
		return eb.Wrapf(err, "db initialize error")
	}

	cacheDir := c.String("cache-dir")
	targets := c.StringSlice("only-update")
	updateInterval := c.Duration("update-interval")
	overridesDir := c.String("overrides")
	eb = eb.With("cache_dir", cacheDir).With("update_interval", updateInterval).With("targets", targets)

	vdb := vulndb.New(cacheDir, outputDir, updateInterval, vulndb.WithOverrides(overridesDir))
	if err := vdb.Build(targets); err != nil {
		return eb.Wrapf(err, "build error")
	}

	return nil
}
