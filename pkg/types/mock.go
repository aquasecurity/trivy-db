package types

import "github.com/stretchr/testify/mock"

type MockVulnSrc struct {
	mock.Mock
}

func (_m *MockVulnSrc) Update(a string) error {
	ret := _m.Called(a)
	return ret.Error(0)
}

func (_m *MockVulnSrc) Get(a, b string) ([]Advisory, error) {
	ret := _m.Called(a, b)
	ret0 := ret.Get(0)
	if ret0 == nil {
		return nil, ret.Error(1)
	}
	r, ok := ret0.([]Advisory)
	if !ok {
		return nil, ret.Error(1)
	}
	return r, ret.Error(1)
}
