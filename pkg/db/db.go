package db

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	"github.com/aquasecurity/trivy-db/pkg/types"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
)

type Type int

const (
	SchemaVersion = 1

	TypeFull Type = iota
	TypeLight
)

var (
	db    *bolt.DB
	dbDir string
)

type Operation interface {
	BatchUpdate(fn func(*bolt.Tx) error) (err error)

	PutVulnerabilityDetail(tx *bolt.Tx, vulnerabilityID string, source string,
		vulnerability types.VulnerabilityDetail) (err error)
	DeleteVulnerabilityDetailBucket() (err error)

	PutAdvisory(tx *bolt.Tx, source string, pkgName string, vulnerabilityID string,
		advisory interface{}) (err error)
	ForEachAdvisory(source string, pkgName string) (value map[string][]byte, err error)
	GetAdvisories(source string, pkgName string) (advisories []types.Advisory, err error)

	PutSeverity(tx *bolt.Tx, vulnerabilityID string, severity types.Severity) (err error)
	GetSeverity(vulnerabilityID string) (severity types.Severity, err error)
	ForEachSeverity(fn func(tx *bolt.Tx, cveID string, severity types.Severity) error) (err error)

	DeleteSeverityBucket() (err error)

	PutVulnerability(tx *bolt.Tx, vulnerabilityID string, vulnerability types.Vulnerability) (err error)
	GetVulnerability(vulnerabilityID string) (vulnerability types.Vulnerability, err error)
}

type Metadata struct {
	Version    int  `json:",omitempty"`
	Type       Type `json:",omitempty"`
	NextUpdate time.Time
	UpdatedAt  time.Time
}

type Config struct {
}

type VulnOperation interface {
	GetVulnerabilityDetail(cveID string) (map[string]types.VulnerabilityDetail, error)
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

func Path(cacheDir string) string {
	dbDir = filepath.Join(cacheDir, "db")
	dbPath := filepath.Join(dbDir, "trivy.db")
	return dbPath
}

func Close() error {
	if err := db.Close(); err != nil {
		return xerrors.Errorf("failed to close DB: %w", err)
	}
	return nil
}

func (dbc Config) GetVersion() int {
	metadata, err := dbc.GetMetadata()
	if err != nil {
		return 0
	}
	return metadata.Version
}
func (dbc Config) GetMetadata() (Metadata, error) {
	var metadata Metadata
	value, err := Config{}.get("trivy", "metadata", "data")
	if err != nil {
		return Metadata{}, err
	}
	if err = json.Unmarshal(value, &metadata); err != nil {
		return Metadata{}, err
	}
	return metadata, nil
}

func (dbc Config) SetMetadata(metadata Metadata) error {
	err := dbc.update("trivy", "metadata", "data", metadata)
	if err != nil {
		return xerrors.Errorf("failed to save metadata: %w", err)
	}
	return nil
}

func (dbc Config) StoreMetadata(metadata Metadata, dir string) error {
	b, err := json.Marshal(metadata)
	if err != nil {
		return xerrors.Errorf("failed to store metadata: %w", err)
	}
	return ioutil.WriteFile(filepath.Join(dir, "metadata.json"), b, 0600)
}

func (dbc Config) BatchUpdate(fn func(tx *bolt.Tx) error) error {
	err := db.Batch(fn)
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}
	return nil
}

func (dbc Config) update(rootBucket, nestedBucket, key string, value interface{}) error {
	err := db.Update(func(tx *bolt.Tx) error {
		return dbc.putNestedBucket(tx, rootBucket, nestedBucket, key, value)
	})
	if err != nil {
		return xerrors.Errorf("error in db update: %w", err)
	}
	return err
}

func (dbc Config) putNestedBucket(tx *bolt.Tx, rootBucket, nestedBucket, key string, value interface{}) error {
	root, err := tx.CreateBucketIfNotExists([]byte(rootBucket))
	if err != nil {
		return xerrors.Errorf("failed to create a bucket: %w", err)
	}
	return dbc.put(root, nestedBucket, key, value)
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

func (dbc Config) get(rootBucket, nestedBucket, key string) (value []byte, err error) {
	err = db.View(func(tx *bolt.Tx) error {
		root := tx.Bucket([]byte(rootBucket))
		if root == nil {
			return nil
		}
		nested := root.Bucket([]byte(nestedBucket))
		if nested == nil {
			return nil
		}
		value = nested.Get([]byte(key))
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("failed to get data from db: %w", err)
	}
	return value, nil
}

func (dbc Config) forEach(rootBucket, nestedBucket string) (value map[string][]byte, err error) {
	value = map[string][]byte{}
	err = db.View(func(tx *bolt.Tx) error {
		root := tx.Bucket([]byte(rootBucket))
		if root == nil {
			return nil
		}
		nested := root.Bucket([]byte(nestedBucket))
		if nested == nil {
			return nil
		}
		err := nested.ForEach(func(k, v []byte) error {
			value[string(k)] = v
			return nil
		})
		if err != nil {
			return xerrors.Errorf("error in db foreach: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("failed to get all key/value in the specified bucket: %w", err)
	}
	return value, nil
}

func (dbc Config) deleteBucket(bucketName string) error {
	return db.Update(func(tx *bolt.Tx) error {
		if err := tx.DeleteBucket([]byte(bucketName)); err != nil {
			return xerrors.Errorf("failed to delete bucket: %w", err)
		}
		return nil
	})
}
