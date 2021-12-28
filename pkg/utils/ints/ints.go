package ints

import "sort"

func Unique(ints []int) []int {
	sort.Ints(ints)

	var ret []int
	var pre int
	for _, num := range ints {
		if pre != num {
			ret = append(ret, num)
		}
		pre = num
	}

	return ret
}

func HasIntersection(list1, list2 []int) bool {
	for _, l1 := range list1 {
		for _, l2 := range list2 {
			if l1 == l2 {
				return true
			}
		}

	}
	return false
}
