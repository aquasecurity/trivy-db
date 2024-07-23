package vulndb

import (
	"log"
	"time"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
	"k8s.io/utils/clock"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/metadata"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

type VulnDB interface {
	Build(targets []string) error
}

type TrivyDB struct {
	dbc            db.Config
	metadata       metadata.Client
	vulnClient     vulnerability.Vulnerability
	vulnSrcs       map[types.SourceID]vulnsrc.VulnSrc
	cacheDir       string
	updateInterval time.Duration
	clock          clock.Clock
}

type Option func(*TrivyDB)

func WithClock(clock clock.Clock) Option {
	return func(core *TrivyDB) {
		core.clock = clock
	}
}

func WithVulnSrcs(srcs map[types.SourceID]vulnsrc.VulnSrc) Option {
	return func(core *TrivyDB) {
		core.vulnSrcs = srcs
	}
}

func New(cacheDir, outputDir string, updateInterval time.Duration, opts ...Option) *TrivyDB {
	// Initialize map
	vulnSrcs := map[types.SourceID]vulnsrc.VulnSrc{}
	for _, v := range vulnsrc.All {
		vulnSrcs[v.Name()] = v
	}

	dbc := db.Config{}
	tdb := &TrivyDB{
		dbc:            dbc,
		metadata:       metadata.NewClient(outputDir),
		vulnClient:     vulnerability.New(dbc),
		vulnSrcs:       vulnSrcs,
		cacheDir:       cacheDir,
		updateInterval: updateInterval,
		clock:          clock.RealClock{},
	}

	for _, opt := range opts {
		opt(tdb)
	}

	return tdb
}

func (t TrivyDB) Insert(targets []string) error {
	log.Println("Updating vulnerability database...")
	for _, target := range targets {
		src, ok := t.vulnSrc(target)
		if !ok {
			return xerrors.Errorf("%s is not supported", target)
		}
		log.Printf("Updating %s data...\n", target)

		if err := src.Update(t.cacheDir); err != nil {
			return xerrors.Errorf("%s update error: %w", target, err)
		}
	}

	md := metadata.Metadata{
		Version:    db.SchemaVersion,
		NextUpdate: t.clock.Now().UTC().Add(t.updateInterval),
		UpdatedAt:  t.clock.Now().UTC(),
	}

	if err := t.metadata.Update(md); err != nil {
		return xerrors.Errorf("metadata update error: %w", err)
	}

	return nil
}

func (t TrivyDB) Build(targets []string) error {
	// Insert all security advisories
	if err := t.Insert(targets); err != nil {
		return xerrors.Errorf("insert error: %w", err)
	}

	// Remove unnecessary details
	if err := t.optimize(); err != nil {
		return xerrors.Errorf("optimize error: %w", err)
	}

	// Remove unnecessary buckets
	if err := t.cleanup(); err != nil {
		return xerrors.Errorf("cleanup error: %w", err)
	}

	return nil
}

func (t TrivyDB) vulnSrc(target string) (vulnsrc.VulnSrc, bool) {
	for _, src := range t.vulnSrcs {
		if target == string(src.Name()) {
			return src, true
		}
	}
	return nil, false
}

func (t TrivyDB) optimize() error {
	// NVD also contains many vulnerabilities that are not related to OS packages or language-specific packages.
	// Trivy DB will not store them so that it could reduce the database size.
	// This bucket has only vulnerability IDs provided by vendors. They must be stored.
	err := t.dbc.ForEachVulnerabilityID(func(tx *bolt.Tx, cveID string) error {
		details := t.vulnClient.GetDetails(cveID)
		if t.vulnClient.IsRejected(details) {
			return nil
		}

		if err := t.dbc.SaveAdvisoryDetails(tx, cveID); err != nil {
			return xerrors.Errorf("failed to save advisories: %w", err)
		}

		if len(details) == 0 {
			return nil
		}

		vuln := t.vulnClient.Normalize(details)
		if err := t.dbc.PutVulnerability(tx, cveID, vuln); err != nil {
			return xerrors.Errorf("failed to put vulnerability: %w", err)
		}

		return nil
	})

	if err != nil {
		return xerrors.Errorf("failed to iterate severity: %w", err)
	}

	return nil
}

func (t TrivyDB) cleanup() error {
	if err := t.dbc.DeleteVulnerabilityIDBucket(); err != nil {
		return xerrors.Errorf("failed to delete severity bucket: %w", err)
	}

	if err := t.dbc.DeleteVulnerabilityDetailBucket(); err != nil {
		return xerrors.Errorf("failed to delete vulnerability detail bucket: %w", err)
	}

	if err := t.dbc.DeleteAdvisoryDetailBucket(); err != nil {
		return xerrors.Errorf("failed to delete advisory detail bucket: %w", err)
	}

	return nil
}
