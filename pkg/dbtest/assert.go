package dbtest

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
)

var (
	ErrNoBucket = xerrors.New("no such bucket")
)

func NoKey(t *testing.T, dbPath string, keys []string, msgAndArgs ...interface{}) {
	t.Helper()

	value := get(t, dbPath, keys)
	assert.Nil(t, value, msgAndArgs...)
}

func NoBucket(t *testing.T, dbPath string, buckets []string, msgAndArgs ...interface{}) {
	t.Helper()

	db := open(t, dbPath)
	defer db.Close()

	err := db.View(func(tx *bolt.Tx) error {
		bkt, err := nestedBuckets(tx, buckets)
		if err != nil {
			return err
		}

		// The specified bucket must not exist.
		assert.Nil(t, bkt, msgAndArgs...)

		return nil
	})

	require.NoError(t, err, msgAndArgs...)
}

func JSONEq(t *testing.T, dbPath string, key []string, want interface{}, msgAndArgs ...interface{}) {
	t.Helper()

	wantByte, err := json.Marshal(want)
	require.NoError(t, err, msgAndArgs)

	got := get(t, dbPath, key)
	assert.JSONEq(t, string(wantByte), string(got), msgAndArgs...)
}

type bucketer interface {
	Bucket(name []byte) *bolt.Bucket
}

func get(t *testing.T, dbPath string, keys []string) []byte {
	if len(keys) < 2 {
		require.Failf(t, "malformed keys: %v", "", keys)
	}
	db := open(t, dbPath)
	defer db.Close()

	var b []byte
	err := db.View(func(tx *bolt.Tx) error {
		bkts, key := keys[:len(keys)-1], keys[len(keys)-1]

		var bucket bucketer = tx
		for _, k := range bkts {
			if reflect.ValueOf(bucket).IsNil() {
				return xerrors.Errorf("bucket error %s: %w", k, ErrNoBucket)
			}
			bucket = bucket.Bucket([]byte(k))
		}
		bkt, ok := bucket.(*bolt.Bucket)
		if !ok {
			return xerrors.Errorf("bucket error %v: %w", keys, ErrNoBucket)
		} else if bkt == nil {
			return xerrors.Errorf("empty bucket %v: %w", keys, ErrNoBucket)
		}
		res := bkt.Get([]byte(key))
		if res == nil {
			return nil
		}

		// Copy the returned value
		b = make([]byte, len(res))
		copy(b, res)
		return nil
	})
	require.NoError(t, err)

	return b
}

func open(t *testing.T, dbPath string) *bolt.DB {
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{ReadOnly: true})
	require.NoError(t, err)

	return db
}

func nestedBuckets(start bucketer, buckets []string) (*bolt.Bucket, error) {
	bucket := start
	for _, k := range buckets {
		if reflect.ValueOf(bucket).IsNil() {
			return nil, xerrors.Errorf("bucket error %v: %w", buckets, ErrNoBucket)
		}
		bucket = bucket.Bucket([]byte(k))
	}
	bkt, ok := bucket.(*bolt.Bucket)
	if !ok {
		return nil, xerrors.Errorf("bucket error %v: %w", buckets, ErrNoBucket)
	}
	return bkt, nil
}
