package db

import (
	"github.com/aquasecurity/trivy-db/pkg/types"
	bolt "github.com/etcd-io/bbolt"
)

func (_m *MockDBConfig) PutSeverity(a *bolt.Tx, b string, c types.Severity) error {
	ret := _m.Called(a, b, c)
	return ret.Error(0)
}

func (_m *MockDBConfig) GetSeverity(a string) (types.Severity, error) {
	ret := _m.Called(a)
	ret0 := ret.Get(0)
	if ret0 == nil {
		return types.SeverityUnknown, ret.Error(1)
	}
	s, ok := ret0.(types.Severity)
	if !ok {
		return types.SeverityUnknown, ret.Error(1)
	}
	return s, ret.Error(1)
}

func (_m *MockDBConfig) ForEachSeverity(f func(tx *bolt.Tx, cveID string, severity types.Severity) error) error {
	ret := _m.Called()
	return ret.Error(0)
}

func (_m *MockDBConfig) DeleteSeverityBucket() error {
	ret := _m.Called()
	return ret.Error(0)
}
