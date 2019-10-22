package db

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/aquasecurity/trivy-db/pkg/types"

	bolt "github.com/etcd-io/bbolt"
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

type Operations interface {
	//SetVersion(int) error
	//Update(string, string, string, interface{}) error
	//Put(*bolt.Bucket, string, string, interface{}) error
	BatchUpdate(func(*bolt.Tx) error) error
	//PutNestedBucket(*bolt.Tx, string, string, string, interface{}) error
	//ForEach(string, string) (map[string][]byte, error)
	PutVulnerabilityDetail(*bolt.Tx, string, string, types.VulnerabilityDetail) error
	PutAdvisory(*bolt.Tx, string, string, string, interface{}) error
	ForEachAdvisory(string, string) (map[string][]byte, error)

	PutSeverity(*bolt.Tx, string, types.Severity) error
	GetSeverity(*bolt.Tx, string) (types.Severity, error)
}

type Metadata struct {
	Version   int
	Type      Type
	UpdatedAt time.Time
}

type Config struct {
}

func Init(cacheDir string) (err error) {
	dbPath := Path(cacheDir)
	dbDir = filepath.Dir(dbPath)
	if err = os.MkdirAll(dbDir, 0700); err != nil {
		return xerrors.Errorf("failed to mkdir: %w", err)
	}

	log.Printf("db path: %s\n", dbPath)
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

func GetVersion() int {
	metadata, err := GetMetadata()
	if err != nil {
		return 0
	}
	return metadata.Version
}
func GetMetadata() (Metadata, error) {
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
