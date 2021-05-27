package pkg

import (
	"github.com/aquasecurity/trivy-db/pkg/utils"
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
	extendedDB := c.Bool("extended-db")
	updater := vulnsrc.NewUpdater(cacheDir, light, updateInterval)
	targetsList := strings.Split(targets, ",")
	if extendedDB {
		if !utils.StringInSlice("arch-linux", targetsList) {
			targetsList = append(targetsList, "arch-linux")
		}
	} else {
		delete(updater.UpdateMap, "arch-linux")
	}

	if err := updater.Update(targetsList); err != nil {
		return err
	}

	return nil

}
