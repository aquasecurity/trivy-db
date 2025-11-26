package main

import (
	"os"

	"github.com/aquasecurity/trivy-db/pkg"
	"github.com/aquasecurity/trivy-db/pkg/log"
)

var (
	version = "0.0.1"
)

func main() {
	ac := pkg.AppConfig{}
	app := ac.NewApp(version)
	err := app.Run(os.Args)
	if err != nil {
		log.Errorf("%+v", err)
		os.Exit(1)
	}
}
