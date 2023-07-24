package types

import "encoding/json"

type Status int

var (
	// Statuses is a list of statuses.
	// VEX has 4 statuses: not-affected, affected, fixed, and under_investigation.
	// cf. https://www.cisa.gov/sites/default/files/2023-04/minimum-requirements-for-vex-508c.pdf
	//
	// In addition to them, Red Hat has "will_not_fix" and "fix_deferred".
	// cf. https://access.redhat.com/blogs/product-security/posts/2066793
	Statuses = []string{
		"unknown",
		"not_affected",
		"affected",
		"fixed",
		"under_investigation",
		"will_not_fix",
		"fix_deferred",
		"end_of_life",
	}
)

const (
	StatusUnknown Status = iota
	StatusNotAffected
	StatusAffected
	StatusFixed
	StatusUnderInvestigation
	StatusWillNotFix // Red Hat specific
	StatusFixDeferred
	StatusEndOfLife
)

func NewStatus(status string) Status {
	for i, s := range Statuses {
		if status == s {
			return Status(i)
		}
	}
	return StatusUnknown
}

func (s *Status) String() string {
	idx := s.Index()
	if idx < 0 || idx >= len(Statuses) {
		idx = 0 // unknown
	}
	return Statuses[idx]
}

func (s *Status) Index() int {
	return int(*s)
}

func (s *Status) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *Status) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	*s = NewStatus(str)
	return nil
}
