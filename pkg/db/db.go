package db

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/types"
)

type CustomPut func(dbc Operation, tx *bolt.Tx, adv interface{}) error

const SchemaVersion = 2

var (
	db    *bolt.DB
	dbDir string
)

type Operation interface {
	BatchUpdate(fn func(*bolt.Tx) error) (err error)

	GetVulnerabilityDetail(cveID string) (detail map[string]types.VulnerabilityDetail, err error)
	PutVulnerabilityDetail(tx *bolt.Tx, vulnerabilityID string, source string,
		vulnerability types.VulnerabilityDetail) (err error)
	DeleteVulnerabilityDetailBucket() (err error)

	PutAdvisory(tx *bolt.Tx, source string, pkgName string, vulnerabilityID string,
		advisory interface{}) (err error)
	ForEachAdvisory(source string, pkgName string) (value map[string]Value, err error)
	GetAdvisories(source string, pkgName string) (advisories []types.Advisory, err error)

	PutVulnerabilityID(tx *bolt.Tx, vulnerabilityID string) (err error)
	ForEachVulnerabilityID(fn func(tx *bolt.Tx, cveID string) error) (err error)

	PutVulnerability(tx *bolt.Tx, vulnerabilityID string, vulnerability types.Vulnerability) (err error)
	GetVulnerability(vulnerabilityID string) (vulnerability types.Vulnerability, err error)

	GetAdvisoryDetails(cveID string) ([]types.AdvisoryDetail, error)
	PutAdvisoryDetail(tx *bolt.Tx, vulnerabilityID string, source string, pkgName string,
		advisory interface{}) (err error)
	DeleteAdvisoryDetailBucket() error

	PutDataSource(tx *bolt.Tx, bktName string, source types.DataSource) (err error)
}

type Config struct {
}

func Init(cacheDir string) (err error) {
	dbPath := Path(cacheDir)
	dbDir = filepath.Dir(dbPath)
	if err = os.MkdirAll(dbDir, 0700); err != nil {
		return xerrors.Errorf("failed to mkdir: %w", err)
	}

	// bbolt sometimes occurs the fatal error of "unexpected fault address".
	// In that case, the local DB should be broken and needs to be removed.
	debug.SetPanicOnFault(true)
	defer func() {
		if r := recover(); r != nil {
			if err = os.Remove(dbPath); err != nil {
				return
			}
			db, err = bolt.Open(dbPath, 0600, nil)
		}
		debug.SetPanicOnFault(false)
	}()

	db, err = bolt.Open(dbPath, 0600, nil)
	if err != nil {
		return xerrors.Errorf("failed to open db: %w", err)
	}
	return nil
}

func Dir(cacheDir string) string {
	return filepath.Join(cacheDir, "db")
}

func Path(cacheDir string) string {
	dbPath := filepath.Join(Dir(cacheDir), "trivy.db")
	return dbPath
}

func Close() error {
	if err := db.Close(); err != nil {
		return xerrors.Errorf("failed to close DB: %w", err)
	}
	return nil
}

func (dbc Config) Connection() *bolt.DB {
	return db
}

func (dbc Config) BatchUpdate(fn func(tx *bolt.Tx) error) error {
	err := db.Batch(fn)
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}
	return nil
}

func (dbc Config) put(root *bolt.Bucket, nestedBucket, key string, value interface{}) error {
	nested, err := root.CreateBucketIfNotExists([]byte(nestedBucket))
	if err != nil {
		return xerrors.Errorf("failed to create a bucket: %w", err)
	}
	v, err := json.Marshal(value)
	if err != nil {
		return xerrors.Errorf("failed to unmarshal JSON: %w", err)
	}
	return nested.Put([]byte(key), v)
}

type Value struct {
	Source  types.DataSource
	Content []byte
}

func (dbc Config) forEach(rootBucket, nestedBucket string) (map[string]Value, error) {
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

			source, _ := dbc.getDataSource(tx, r)

			nested := root.Bucket([]byte(nestedBucket))
			if nested == nil {
				continue
			}

			err := nested.ForEach(func(k, v []byte) error {
				values[string(k)] = Value{
					Source:  source,
					Content: v,
				}
				return nil
			})
			if err != nil {
				return xerrors.Errorf("error in db foreach: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("failed to get all key/value in the specified bucket: %w", err)
	}
	return values, nil
}

func (dbc Config) deleteBucket(bucketName string) error {
	return db.Update(func(tx *bolt.Tx) error {
		if err := tx.DeleteBucket([]byte(bucketName)); err != nil {
			return xerrors.Errorf("failed to delete bucket: %w", err)
		}
		return nil
	})
}
