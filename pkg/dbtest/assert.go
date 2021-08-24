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

func JSONEq(t *testing.T, dbPath string, key []string, want interface{}, msgAndArgs ...interface{}) {
	t.Helper()

	wantByte, err := json.Marshal(want)
	require.NoError(t, err, msgAndArgs)

	got, err := get(dbPath, key)
	require.NoError(t, err, msgAndArgs...)

	assert.JSONEq(t, string(wantByte), string(got), msgAndArgs...)
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
	defer db.Close()

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
		res := bkt.Get([]byte(key))

		// Copy the returned value
		b = make([]byte, len(res))
		copy(b, res)
		return nil
	})
	return b, err
}
