package vulndb

import (
	"log"
	"path/filepath"
	"time"

	"golang.org/x/xerrors"
	"k8s.io/utils/clock"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

type VulnDB interface {
	Build(targets []string) error
}

type Core struct {
	dbc            db.Config
	vulnClient     vulnerability.Vulnerability
	vulnSrcs       map[string]vulnsrc.VulnSrc
	cacheDir       string
	updateInterval time.Duration
	clock          clock.Clock
}

type Option func(*Core)

func WithClock(clock clock.Clock) Option {
	return func(core *Core) {
		core.clock = clock
	}
}

func WithVulnSrcs(srcs map[string]vulnsrc.VulnSrc) Option {
	return func(core *Core) {
		core.vulnSrcs = srcs
	}
}

func NewCore(cacheDir string, updateInterval time.Duration, opts ...Option) *Core {
	// Initialize map
	vulnSrcs := map[string]vulnsrc.VulnSrc{}
	for _, v := range vulnsrc.All {
		vulnSrcs[v.Name()] = v
	}

	dbc := db.Config{}
	core := &Core{
		dbc:            dbc,
		vulnClient:     vulnerability.New(dbc),
		vulnSrcs:       vulnSrcs,
		cacheDir:       cacheDir,
		updateInterval: updateInterval,
		clock:          clock.RealClock{},
	}

	for _, opt := range opts {
		opt(core)
	}

	return core
}

func (c Core) Insert(dbType db.Type, targets []string) error {
	log.Println("Updating vulnerability database...")
	for _, target := range targets {
		src, ok := c.vulnSrc(target)
		if !ok {
			return xerrors.Errorf("%s is not supported", target)
		}
		log.Printf("Updating %s data...\n", target)

		if err := src.Update(c.cacheDir); err != nil {
			return xerrors.Errorf("%s update error: %w", target, err)
		}
	}

	md := db.Metadata{
		Version:    db.SchemaVersion,
		Type:       dbType,
		NextUpdate: c.clock.Now().UTC().Add(c.updateInterval),
		UpdatedAt:  c.clock.Now().UTC(),
	}

	err := c.dbc.SetMetadata(md)
	if err != nil {
		return xerrors.Errorf("failed to save metadata: %w", err)
	}

	err = c.dbc.StoreMetadata(md, filepath.Join(c.cacheDir, "db"))
	if err != nil {
		return xerrors.Errorf("failed to store metadata: %w", err)
	}

	return nil
}

func (c Core) vulnSrc(target string) (vulnsrc.VulnSrc, bool) {
	for _, src := range c.vulnSrcs {
		if target == src.Name() {
			return src, true
		}
	}
	return nil, false
}

func New(dbType db.Type, cacheDir string, updateInterval time.Duration, opts ...Option) VulnDB {
	core := NewCore(cacheDir, updateInterval, opts...)

	switch dbType {
	case db.TypeLight:
		return lightDB{Core: core}
	default:
		return fullDB{Core: core}
	}
}
