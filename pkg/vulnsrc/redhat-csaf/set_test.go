package redhatcsaf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSet(t *testing.T) {
	s := NewSet[int]()
	assert.NotNil(t, s)
	assert.Empty(t, s.Values())
}

func TestSet_Append(t *testing.T) {
	s := NewSet[int]()
	s.Append(1, 2, 3)
	assert.Equal(t, 3, len(s.Values()))
	assert.Contains(t, s.Values(), 1)
	assert.Contains(t, s.Values(), 2)
	assert.Contains(t, s.Values(), 3)
}

func TestSet_Contains(t *testing.T) {
	s := NewSet[string]()
	s.Append("foo", "bar")
	assert.True(t, s.Contains("foo"))
	assert.True(t, s.Contains("bar"))
	assert.False(t, s.Contains("baz"))
}

func TestSet_Values(t *testing.T) {
	s := NewSet[int]()
	s.Append(3, 1, 2)
	values := s.Values()
	assert.ElementsMatch(t, []int{1, 2, 3}, values)
}

func TestNewOrderedSet(t *testing.T) {
	s := NewOrderedSet[int]()
	assert.NotNil(t, s)
	assert.Empty(t, s.Values())
}

func TestOrderedSet_Values(t *testing.T) {
	s := NewOrderedSet[int]()
	s.Append(3, 1, 2)
	values := s.Values()
	assert.Equal(t, []int{1, 2, 3}, values)
}
