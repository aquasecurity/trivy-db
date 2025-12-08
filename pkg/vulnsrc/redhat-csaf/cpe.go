package redhatcsaf

import (
	"sort"

	"github.com/samber/lo"
)

type CPEList []string

func (l CPEList) Index(cpe string) int {
	return lo.IndexOf(l, cpe)
}

func (l CPEList) Indices(cpes []string) []int {
	indices := lo.Map(cpes, func(cpe string, _ int) int {
		return l.Index(cpe)
	})
	sort.Ints(indices)
	return indices
}
