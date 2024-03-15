package pkg

import (
	"fmt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/vulndb"
	"github.com/urfave/cli"
	"golang.org/x/xerrors"
)

func timestamp(c *cli.Context) error {
	cacheDir := c.String("cache-dir")
	if err := db.Init(cacheDir); err != nil {
		return xerrors.Errorf("db initialize error: %w", err)
	}
	updateInterval := c.Duration("update-interval")
	vdb := vulndb.New(cacheDir, updateInterval)
	ts, err := vdb.Timestamp()
	if err != nil {
		return err
	}
	fmt.Println(ts)
	return nil
}
