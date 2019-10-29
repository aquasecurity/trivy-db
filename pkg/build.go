package pkg

import (
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc"
	"github.com/urfave/cli"
)

func build(c *cli.Context) error {
	cacheDir := c.String("cache-dir")
	if err := db.Init(cacheDir); err != nil {
		return err
	}

	targets := c.String("only-update")
	light := c.Bool("light")
	updateInterval := c.Duration("update-interval")
	if err := vulnsrc.Update(strings.Split(targets, ","), cacheDir, light, updateInterval); err != nil {
		return err
	}

	return nil

}
