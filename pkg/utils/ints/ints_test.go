package ints_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-db/pkg/utils/ints"
)

func TestHasIntersection(t *testing.T) {
	type args struct {
		list1 []int
		list2 []int
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "happy path",
			args: args{
				list1: []int{1, 2, 4},
				list2: []int{3, 4, 5},
			},
			want: true,
		},
		{
			name: "sad path",
			args: args{
				list1: []int{1, 2, 3},
				list2: []int{4, 5, 6},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ints.HasIntersection(tt.args.list1, tt.args.list2)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestUnique(t *testing.T) {
	tests := []struct {
		name string
		ints []int
		want []int
	}{
		{
			name: "happy path",
			ints: []int{1, 3, 1, 2, 3},
			want: []int{1, 2, 3},
		},
		{
			name: "length 1",
			ints: []int{1},
			want: []int{1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ints.Unique(tt.ints)
			assert.Equal(t, tt.want, got)
		})
	}
}
