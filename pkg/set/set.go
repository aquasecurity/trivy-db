package set

import (
	"sort"

	"golang.org/x/exp/constraints"
)

// ------------------------------------------
// Generic Set implementation (thread-unsafe)
// ------------------------------------------

// Set represents a generic set of comparable items
type Set[T comparable] struct {
	items map[T]struct{}
}

// New creates a new Set
func New[T comparable]() Set[T] {
	return Set[T]{
		items: make(map[T]struct{}),
	}
}

// Append inserts elements into the set
func (s Set[T]) Append(elems ...T) {
	for _, elem := range elems {
		s.items[elem] = struct{}{}
	}
}

// Contains checks if an element is in the set
func (s Set[T]) Contains(elem T) bool {
	_, ok := s.items[elem]
	return ok
}

// Values returns all elements in the set as an unsorted slice
func (s Set[T]) Values() []T {
	v := make([]T, 0, len(s.items))
	for elem := range s.items {
		v = append(v, elem)
	}
	return v
}

// Ordered is a set of ordered elements that supports sorted Values
type Ordered[T constraints.Ordered] struct {
	Set[T]
}

// NewOrdered creates a new Ordered set
func NewOrdered[T constraints.Ordered]() Ordered[T] {
	return Ordered[T]{
		Set: New[T](),
	}
}

// Values returns all elements in the set as a sorted slice
func (s Ordered[T]) Values() []T {
	v := s.Set.Values()
	sort.Slice(v, func(i, j int) bool {
		return v[i] < v[j]
	})
	return v
}
