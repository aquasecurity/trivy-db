package db

import (
	"github.com/aquasecurity/trivy-db/pkg/types"
	bolt "github.com/etcd-io/bbolt"
	"github.com/stretchr/testify/mock"
)

type MockDBConfig struct {
	mock.Mock
}

type GetAdvisoriesArgs struct {
	Source          string
	SourceAnything  bool
	PkgName         string
	PkgNameAnything bool
}

type GetAdvisoriesReturns struct {
	Advisories []types.Advisory
	Err        error
}

type GetAdvisoriesExpectation struct {
	Args    GetAdvisoriesArgs
	Returns GetAdvisoriesReturns
}

func (_m *MockDBConfig) ApplyGetAdvisoriesExpectation(e GetAdvisoriesExpectation) {
	var args []interface{}
	if e.Args.SourceAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.Source)
	}
	if e.Args.PkgNameAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.PkgName)
	}
	_m.On("GetAdvisories", args...).Return(e.Returns.Advisories, e.Returns.Err)
}

func (_m *MockDBConfig) ApplyGetAdvisoriesExpectations(expectations []GetAdvisoriesExpectation) {
	for _, e := range expectations {
		_m.ApplyGetAdvisoriesExpectation(e)
	}
}

type PutAdvisoryArgs struct {
	Tx                      *bolt.Tx
	TxAnything              bool
	Source                  string
	SourceAnything          bool
	PkgName                 string
	PkgNameAnything         bool
	VulnerabilityID         string
	VulnerabilityIDAnything bool
	Advisory                interface{}
	AdvisoryAnything        bool
}

type PutAdvisoryReturns struct {
	Err error
}

type PutAdvisoryExpectation struct {
	Args    PutAdvisoryArgs
	Returns PutAdvisoryReturns
}

func (_m *MockDBConfig) ApplyPutAdvisoryExpectation(e PutAdvisoryExpectation) {
	var args []interface{}
	if e.Args.TxAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.Tx)
	}
	if e.Args.SourceAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.Source)
	}
	if e.Args.PkgNameAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.PkgName)
	}
	if e.Args.VulnerabilityIDAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.VulnerabilityID)
	}
	if e.Args.AdvisoryAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.Advisory)
	}
	_m.On("PutAdvisory", args...).Return(e.Returns.Err)
}

func (_m *MockDBConfig) ApplyPutAdvisoryExpectations(expectations []PutAdvisoryExpectation) {
	for _, e := range expectations {
		_m.ApplyPutAdvisoryExpectation(e)
	}
}

func (_m *MockDBConfig) SetVersion(version int) error {
	ret := _m.Called(version)
	return ret.Error(0)
}

func (_m *MockDBConfig) GetMetadata() (Metadata, error) {
	ret := _m.Called()
	ret0 := ret.Get(0)
	if ret0 == nil {
		return Metadata{}, ret.Error(1)
	}
	metadata, ok := ret0.(Metadata)
	if !ok {
		return Metadata{}, ret.Error(1)
	}
	return metadata, nil
}

func (_m *MockDBConfig) SetMetadata(a Metadata) error {
	ret := _m.Called(a)
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

func (_m *MockDBConfig) PutVulnerability(a *bolt.Tx, b string, c types.Vulnerability) error {
	ret := _m.Called(a, b, c)
	return ret.Error(0)
}

func (_m *MockDBConfig) GetVulnerability(a string) (types.Vulnerability, error) {
	ret := _m.Called(a)
	ret0 := ret.Get(0)
	if ret0 == nil {
		return types.Vulnerability{}, ret.Error(1)
	}
	v, ok := ret0.(types.Vulnerability)
	if !ok {
		return types.Vulnerability{}, ret.Error(1)
	}
	return v, ret.Error(1)
}
