package db

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
)

type CustomPut func(dbc Operation, tx *bolt.Tx, adv any) error

const (
	SchemaVersion        = 2
	defaultDBOpenTimeout = 5 * time.Second
)

var db *bolt.DB

type Operation interface {
	BatchUpdate(fn func(*bolt.Tx) error) (err error)

	GetVulnerabilityDetail(cveID string) (detail map[types.SourceID]types.VulnerabilityDetail, err error)
	PutVulnerabilityDetail(tx *bolt.Tx, vulnerabilityID string, source types.SourceID,
		vulnerability types.VulnerabilityDetail) (err error)
	DeleteVulnerabilityDetailBucket() (err error)

	ForEachAdvisory(sources []string, pkgName string) (value map[string]Value, err error)
	GetAdvisories(source string, pkgName string) (advisories []types.Advisory, err error)

	PutVulnerabilityID(tx *bolt.Tx, vulnerabilityID string) (err error)
	ForEachVulnerabilityID(fn func(tx *bolt.Tx, cveID string) error) (err error)

	PutVulnerability(tx *bolt.Tx, vulnerabilityID string, vulnerability types.Vulnerability) (err error)
	GetVulnerability(vulnerabilityID string) (vulnerability types.Vulnerability, err error)

	SaveAdvisoryDetails(tx *bolt.Tx, cveID string) (err error)
	PutAdvisoryDetail(tx *bolt.Tx, vulnerabilityID, pkgName string, nestedBktNames []string, advisory any) (err error)
	DeleteAdvisoryDetailBucket() error

	PutDataSource(tx *bolt.Tx, bktName string, source types.DataSource) (err error)

	// For Red Hat
	PutRedHatRepositories(tx *bolt.Tx, repository string, cpeIndices []int) (err error)
	PutRedHatNVRs(tx *bolt.Tx, nvr string, cpeIndices []int) (err error)
	PutRedHatCPEs(tx *bolt.Tx, cpeIndex int, cpe string) (err error)
	RedHatRepoToCPEs(repository string) (cpeIndices []int, err error)
	RedHatNVRToCPEs(nvr string) (cpeIndices []int, err error)
}

type Getter interface {
	Get(GetParams) ([]types.Advisory, error)
}

type GetParams struct {
	Release string
	PkgName string
	Arch    string
}

type Config struct{}

type Option func(*Options)

type Options struct {
	boltOptions *bolt.Options
}

func WithBoltOptions(boltOpts *bolt.Options) Option {
	return func(opts *Options) {
		opts.boltOptions = boltOpts
	}
}

func Init(dbDir string, opts ...Option) (err error) {
	dbOptions := &Options{
		boltOptions: &bolt.Options{
			Timeout: defaultDBOpenTimeout,
		},
	}
	for _, opt := range opts {
		opt(dbOptions)
	}

	eb := oops.With("db_dir", dbDir).With("database", "bbolt")
	if err = os.MkdirAll(dbDir, 0o700); err != nil {
		return eb.Wrapf(err, "failed to mkdir")
	}
	dbPath := Path(dbDir)
	eb = eb.With("db_path", dbPath)

	// bbolt sometimes occurs the fatal error of "unexpected fault address".
	// In that case, the local DB should be broken and needs to be removed.
	debug.SetPanicOnFault(true)
	defer func() {
		if r := recover(); r != nil {
			if err = os.Remove(dbPath); err != nil {
				return
			}
			err = eb.Errorf("db corrupted: %s", r)
		}
		debug.SetPanicOnFault(false)
	}()

	db, err = bolt.Open(dbPath, 0o644, dbOptions.boltOptions)
	if err != nil {
		// Check if the error is due to timeout (database locked by another process)
		if errors.Is(err, bolt.ErrTimeout) {
			return eb.Wrapf(err, "vulnerability database may be in use by another process")
		}
		return eb.Wrapf(err, "failed to open db")
	}
	return nil
}

func Path(dbDir string) string {
	dbPath := filepath.Join(dbDir, "trivy.db")
	return dbPath
}

func Close() error {
	// Skip closing the database if the connection is not established.
	if db == nil {
		return nil
	}
	if err := db.Close(); err != nil {
		return oops.Wrapf(err, "failed to close DB")
	}
	return nil
}

func (dbc Config) Connection() *bolt.DB {
	return db
}

func (dbc Config) BatchUpdate(fn func(tx *bolt.Tx) error) error {
	err := db.Batch(fn)
	if err != nil {
		return oops.Wrapf(err, "batch update error")
	}
	return nil
}

func (dbc Config) put(tx *bolt.Tx, bktNames []string, key string, value any) error {
	if len(bktNames) == 0 {
		return oops.Errorf("empty bucket name")
	}

	eb := oops.With("bucket_names", bktNames)
	bkt, err := tx.CreateBucketIfNotExists([]byte(bktNames[0]))
	if err != nil {
		return eb.With("bucket_name", bktNames[0]).Wrapf(err, "failed to create bucket")
	}

	for _, bktName := range bktNames[1:] {
		bkt, err = bkt.CreateBucketIfNotExists([]byte(bktName))
		if err != nil {
			return eb.With("bucket_name", bktName).Wrapf(err, "failed to create bucket")
		}
	}
	v, err := json.Marshal(value)
	if err != nil {
		return eb.Wrapf(err, "json marshal error")
	}

	return bkt.Put([]byte(key), v)
}

func (dbc Config) get(bktNames []string, key string) (value []byte, err error) {
	eb := oops.With("bucket_names", bktNames)
	err = db.View(func(tx *bolt.Tx) error {
		if len(bktNames) == 0 {
			return eb.Errorf("empty bucket name")
		}

		bkt := tx.Bucket([]byte(bktNames[0]))
		if bkt == nil {
			return nil
		}
		for _, bktName := range bktNames[1:] {
			bkt = bkt.Bucket([]byte(bktName))
			if bkt == nil {
				return nil
			}
		}
		dbValue := bkt.Get([]byte(key))

		// Copy the byte slice so it can be used outside of the current transaction
		value = make([]byte, len(dbValue))
		copy(value, dbValue)

		return nil
	})
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get data from db")
	}
	return value, nil
}

type Value struct {
	Source  types.DataSource
	Content []byte
}

func (dbc Config) forEach(bktNames []string) (map[string]Value, error) {
	eb := oops.With("bucket_names", bktNames)
	if len(bktNames) < 2 {
		return nil, eb.Errorf("bucket must be nested")
	}
	rootBucket, nestedBuckets := bktNames[0], bktNames[1:]

	values := map[string]Value{}
	err := db.View(func(tx *bolt.Tx) error {
		var rootBuckets []string

		if strings.Contains(rootBucket, "::") {
			// e.g. "pip::", "rubygems::"
			prefix := []byte(rootBucket)
			c := tx.Cursor()
			for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
				rootBuckets = append(rootBuckets, string(k))
			}
		} else {
			// e.g. "GitHub Security Advisory Composer"
			rootBuckets = append(rootBuckets, rootBucket)
		}

		for _, r := range rootBuckets {
			root := tx.Bucket([]byte(r))
			if root == nil {
				continue
			}

			source, err := dbc.getDataSource(tx, r)
			if err != nil {
				log.WithPrefix("db").Debug("Data source error", log.Err(err))
			}

			bkt := root
			for _, nestedBkt := range nestedBuckets {
				bkt = bkt.Bucket([]byte(nestedBkt))
				if bkt == nil {
					break
				}
			}
			if bkt == nil {
				continue
			}

			err = bkt.ForEach(func(k, v []byte) error {
				if len(v) == 0 {
					return nil
				}
				// Copy the byte slice so it can be used outside of the current transaction
				copiedContent := make([]byte, len(v))
				copy(copiedContent, v)

				values[string(k)] = Value{
					Source:  source,
					Content: copiedContent,
				}
				return nil
			})
			if err != nil {
				return eb.Wrapf(err, "db foreach error")
			}
		}
		return nil
	})
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get all key/value in the specified bucket")
	}
	return values, nil
}

func (dbc Config) deleteBucket(bucketName string) error {
	return db.Update(func(tx *bolt.Tx) error {
		if err := tx.DeleteBucket([]byte(bucketName)); err != nil {
			return oops.With("bucket_name", bucketName).Wrapf(err, "failed to delete bucket")
		}
		return nil
	})
}
