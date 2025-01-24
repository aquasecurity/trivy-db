package dbtest

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/samber/oops"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

var (
	ErrNoBucket = oops.Errorf("no such bucket")
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
	require.NoError(t, err, msgAndArgs...)

	got := get(t, dbPath, key, msgAndArgs...)
	assert.JSONEq(t, string(wantByte), string(got), msgAndArgs...)
}

type bucketer interface {
	Bucket(name []byte) *bolt.Bucket
}

func get(t *testing.T, dbPath string, keys []string, msgAndArgs ...interface{}) []byte {
	if len(keys) < 2 {
		require.Failf(t, "malformed keys: %v", "", keys)
	}
	db := open(t, dbPath)
	defer db.Close()

	var b []byte
	err := db.View(func(tx *bolt.Tx) error {
		bkts, key := keys[:len(keys)-1], keys[len(keys)-1]
		eb := oops.With("bucket_names", bkts).With("key", key)

		var bucket bucketer = tx
		for _, k := range bkts {
			if reflect.ValueOf(bucket).IsNil() {
				return eb.With("bucket_name", k).Wrapf(ErrNoBucket, "bucket error")
			}
			bucket = bucket.Bucket([]byte(k))
		}
		bkt, ok := bucket.(*bolt.Bucket)
		if !ok {
			return eb.Wrapf(ErrNoBucket, "bucket error")
		} else if bkt == nil {
			return eb.Wrapf(ErrNoBucket, "empty bucket")
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
	require.NoError(t, err, msgAndArgs...)

	return b
}

func open(t *testing.T, dbPath string) *bolt.DB {
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{ReadOnly: true})
	require.NoError(t, err)

	return db
}

func nestedBuckets(start bucketer, buckets []string) (*bolt.Bucket, error) {
	eb := oops.With("bucket_names", buckets)
	bucket := start
	for _, k := range buckets {
		if reflect.ValueOf(bucket).IsNil() {
			return nil, eb.With("bucket_name", k).Wrapf(ErrNoBucket, "bucket error")
		}
		bucket = bucket.Bucket([]byte(k))
	}
	bkt, ok := bucket.(*bolt.Bucket)
	if !ok {
		return nil, eb.Wrapf(ErrNoBucket, "bucket error")
	}
	return bkt, nil
}
