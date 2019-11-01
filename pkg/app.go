package pkg

import (
	"strings"
	"time"

	"github.com/aquasecurity/trivy-db/pkg/github"

	"github.com/aquasecurity/trivy-db/pkg/utils"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc"
	"github.com/urfave/cli"
)

type AppConfig struct {
	Client github.VCSClientInterface
}

func (ac *AppConfig) NewApp(version string) *cli.App {
	app := cli.NewApp()
	app.Name = "trivy-db"
	app.Version = version
	app.ArgsUsage = "image_name"
	app.Usage = "Trivy DB builder"

	app.Commands = []cli.Command{
		{
			Name:   "build",
			Usage:  "build a database file",
			Action: build,
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "light",
					Usage: "insert only CVE-ID and severity",
				},
				cli.StringFlag{
					Name:  "only-update",
					Usage: "update db only specified distribution (comma separated)",
					Value: strings.Join(vulnsrc.UpdateList, ","),
				},
				cli.StringFlag{
					Name:  "cache-dir",
					Usage: "cache directory path",
					Value: utils.CacheDir(),
				},
				cli.DurationFlag{
					Name:   "update-interval",
					Usage:  "update interval",
					Value:  24 * time.Hour,
					EnvVar: "UPDATE_INTERVAL",
				},
			},
		},
		{
			Name:   "upload",
			Usage:  "upload database files to GitHub Release",
			Action: ac.upload,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "dir",
					Usage: "dir",
					Value: strings.Join(vulnsrc.UpdateList, ","),
				},
			},
		},
	}

	return app
}
