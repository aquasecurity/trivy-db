package db

import (
	"github.com/aquasecurity/trivy-db/pkg/types"
	bolt "github.com/etcd-io/bbolt"
	"github.com/stretchr/testify/mock"
)

type PutSeverityArgs struct {
	Tx                      *bolt.Tx
	TxAnything              bool
	VulnerabilityID         string
	VulnerabilityIDAnything bool
	Severity                types.Severity
	SeverityAnything        bool
}

type PutSeverityReturns struct {
	Err error
}

type PutSeverityExpectation struct {
	Args    PutSeverityArgs
	Returns PutSeverityReturns
}

func (_m *MockDBConfig) ApplyPutSeverityExpectation(e PutSeverityExpectation) {
	var args []interface{}
	if e.Args.TxAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.Tx)
	}
	if e.Args.VulnerabilityIDAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.VulnerabilityID)
	}
	if e.Args.SeverityAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.Severity)
	}
	_m.On("PutSeverity", args...).Return(e.Returns.Err)
}

func (_m *MockDBConfig) ApplyPutSeverityExpectations(expectations []PutSeverityExpectation) {
	for _, e := range expectations {
		_m.ApplyPutSeverityExpectation(e)
	}
}

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
