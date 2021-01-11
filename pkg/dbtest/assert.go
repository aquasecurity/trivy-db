package dbtest

import (
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

func JSONEq(t *testing.T, dbPath string, key []string, want string, msgAndArgs ...interface{}) {
	t.Helper()

	got, err := get(dbPath, key)
	require.NoError(t, err, msgAndArgs)
	assert.JSONEq(t, want, string(got), msgAndArgs)
}

type bucketer interface {
	Bucket(name []byte) *bolt.Bucket
}

func get(dbPath string, keys []string) ([]byte, error) {
	if len(keys) < 2 {
		return nil, xerrors.Errorf("malformed keys: %v", keys)
	}
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{ReadOnly: true})
	if err != nil {
		return nil, err
	}

	var b []byte
	err = db.View(func(tx *bolt.Tx) error {
		bkts, key := keys[:len(keys)-1], keys[len(keys)-1]

		var bucket bucketer = tx
		for _, k := range bkts {
			if reflect.ValueOf(bucket).IsNil() {
				return xerrors.Errorf("bucket error %v: %w", keys, ErrNoBucket)
			}
			bucket = bucket.Bucket([]byte(k))
		}
		bkt, ok := bucket.(*bolt.Bucket)
		if !ok {
			return xerrors.Errorf("bucket error %v: %w", keys, ErrNoBucket)
		}
		b = bkt.Get([]byte(key))
		return nil
	})
	return b, err
}
