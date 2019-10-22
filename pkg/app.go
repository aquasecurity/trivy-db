package pkg

import (
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/utils"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc"
	"github.com/urfave/cli"
)

func NewApp(version string) *cli.App {
	app := cli.NewApp()
	app.Name = "trivy-db"
	app.Version = version
	app.ArgsUsage = "image_name"

	app.Usage = "Trivy DB updater"

	app.Commands = []cli.Command{
		{
			Name:   "build",
			Usage:  "build database",
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
			},
		},
		{
			Name:   "upload",
			Usage:  "upload database files",
			Action: upload,
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
