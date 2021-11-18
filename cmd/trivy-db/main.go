package main

import (
	"context"
	"log"
	"os"

	"github.com/aquasecurity/trivy-db/pkg/github"

	"github.com/aquasecurity/trivy-db/pkg"
)

var (
	version = "0.0.1"
)

func main() {
	ctx := context.Background()
	ac := pkg.AppConfig{
		Client: github.NewClient(ctx),
	}

	app := ac.NewApp(version)
	err := app.Run(os.Args)
	if err != nil {
		log.Fatalf("%+v", err)
	}
}
