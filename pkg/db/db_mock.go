package db

import (
	"github.com/aquasecurity/trivy-db/pkg/types"
	bolt "github.com/etcd-io/bbolt"
	"github.com/stretchr/testify/mock"
)

type MockDBConfig struct {
	mock.Mock
}

func (_m *MockDBConfig) SetVersion(version int) error {
	ret := _m.Called(version)
	return ret.Error(0)
}

func (_m *MockDBConfig) Update(a, b, c string, d interface{}) error {
	ret := _m.Called(a, b, c, d)
	return ret.Error(0)
}

func (_m *MockDBConfig) BatchUpdate(f func(*bolt.Tx) error) error {
	ret := _m.Called(f)
	return ret.Error(0)
}

func (_m *MockDBConfig) PutNestedBucket(a *bolt.Tx, b, c, d string, e interface{}) error {
	ret := _m.Called(a, b, c, d, e)
	return ret.Error(0)
}

func (_m *MockDBConfig) ForEach(a string, b string) (map[string][]byte, error) {
	ret := _m.Called(a, b)
	ret0 := ret.Get(0)
	if ret0 == nil {
		return nil, ret.Error(1)
	}
	r, ok := ret0.(map[string][]byte)
	if !ok {
		return nil, ret.Error(1)
	}
	return r, ret.Error(1)
}

func (_m *MockDBConfig) PutVulnerabilityDetail(a *bolt.Tx, b, c string, d types.VulnerabilityDetail) error {
	ret := _m.Called(a, b, c, d)
	return ret.Error(0)
}

func (_m *MockDBConfig) PutAdvisory(a *bolt.Tx, b, c, d string, e interface{}) error {
	ret := _m.Called(a, b, c, d, e)
	return ret.Error(0)
}

func (_m *MockDBConfig) GetAdvisories(a, b string) ([]types.Advisory, error) {
	ret := _m.Called(a, b)
	ret0 := ret.Get(0)
	if ret0 == nil {
		return nil, ret.Error(1)
	}
	advisories, ok := ret0.([]types.Advisory)
	if !ok {
		return nil, ret.Error(1)
	}
	return advisories, ret.Error(1)
}

func (_m *MockDBConfig) ForEachAdvisory(a, b string) (map[string][]byte, error) {
	ret := _m.Called(a, b)
	ret0 := ret.Get(0)
	if ret0 == nil {
		return nil, ret.Error(1)
	}
	r, ok := ret0.(map[string][]byte)
	if !ok {
		return nil, ret.Error(1)
	}
	return r, ret.Error(1)
}

func (_m *MockDBConfig) PutSeverity(a *bolt.Tx, b string, c types.Severity) error {
	ret := _m.Called(a, b, c)
	return ret.Error(0)
}

func (_m *MockDBConfig) GetSeverity(a *bolt.Tx, b string) (types.Severity, error) {
	ret := _m.Called(a, b)
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
