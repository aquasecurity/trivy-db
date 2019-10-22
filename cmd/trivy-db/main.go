package main

import (
	"log"
	"os"

	"github.com/aquasecurity/trivy-db/pkg"
)

var (
	version = "0.0.1"
)

func main() {
	app := pkg.NewApp(version)
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
