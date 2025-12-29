package set_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-db/pkg/set"
)

func TestNew(t *testing.T) {
	s := set.New[int]()
	assert.NotNil(t, s)
	assert.Empty(t, s.Values())
}

func TestSet_Append(t *testing.T) {
	s := set.New[int]()
	s.Append(1, 2, 3)
	assert.Len(t, s.Values(), 3)
	assert.Contains(t, s.Values(), 1)
	assert.Contains(t, s.Values(), 2)
	assert.Contains(t, s.Values(), 3)
}

func TestSet_Contains(t *testing.T) {
	s := set.New[string]()
	s.Append("foo", "bar")
	assert.True(t, s.Contains("foo"))
	assert.True(t, s.Contains("bar"))
	assert.False(t, s.Contains("baz"))
}

func TestSet_Values(t *testing.T) {
	s := set.New[int]()
	s.Append(3, 1, 2)
	assert.ElementsMatch(t, []int{1, 2, 3}, s.Values())
}

func TestNewOrdered(t *testing.T) {
	s := set.NewOrdered[int]()
	assert.NotNil(t, s)
	assert.Empty(t, s.Values())
}

func TestOrdered_Values(t *testing.T) {
	s := set.NewOrdered[int]()
	s.Append(3, 1, 2)
	assert.Equal(t, []int{1, 2, 3}, s.Values())
}
