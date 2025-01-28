package vulndb

import (
	"time"

	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"
	"k8s.io/utils/clock"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/log"
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
	log.Info("Updating vulnerability database...")
	eb := oops.In("db")

	for _, target := range targets {
		eb := eb.With("target", target)
		src, ok := t.vulnSrc(target)
		if !ok {
			return eb.Errorf("target not supported")
		}
		log.WithPrefix(target).Info("Updating data...")

		if err := src.Update(t.cacheDir); err != nil {
			return eb.Wrapf(err, "update error")
		}
	}

	md := metadata.Metadata{
		Version:    db.SchemaVersion,
		NextUpdate: t.clock.Now().UTC().Add(t.updateInterval),
		UpdatedAt:  t.clock.Now().UTC(),
	}

	if err := t.metadata.Update(md); err != nil {
		return eb.Wrapf(err, "metadata update error")
	}

	return nil
}

func (t TrivyDB) Build(targets []string) error {
	eb := oops.In("db")

	// Insert all security advisories
	if err := t.Insert(targets); err != nil {
		return eb.Wrapf(err, "insert error")
	}

	// Remove unnecessary details
	if err := t.optimize(); err != nil {
		return eb.Wrapf(err, "optimize error")
	}

	// Remove unnecessary buckets
	if err := t.cleanup(); err != nil {
		return eb.Wrapf(err, "cleanup error")
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
		eb := oops.With("vuln_id", cveID)
		details := t.vulnClient.GetDetails(cveID)
		if t.vulnClient.IsRejected(details) {
			return nil
		}

		if err := t.dbc.SaveAdvisoryDetails(tx, cveID); err != nil {
			return eb.Wrapf(err, "failed to save advisories")
		}

		if len(details) == 0 {
			return nil
		}

		vuln := t.vulnClient.Normalize(details)
		if err := t.dbc.PutVulnerability(tx, cveID, vuln); err != nil {
			return eb.Wrapf(err, "failed to put vulnerability")
		}

		return nil
	})

	if err != nil {
		return oops.Wrapf(err, "failed to iterate severity")
	}

	return nil
}

func (t TrivyDB) cleanup() error {
	if err := t.dbc.DeleteVulnerabilityIDBucket(); err != nil {
		return oops.Wrapf(err, "failed to delete severity bucket")
	}

	if err := t.dbc.DeleteVulnerabilityDetailBucket(); err != nil {
		return oops.Wrapf(err, "failed to delete vulnerability detail bucket")
	}

	if err := t.dbc.DeleteAdvisoryDetailBucket(); err != nil {
		return oops.Wrapf(err, "failed to delete advisory detail bucket")
	}

	return nil
}
