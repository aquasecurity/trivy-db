package types

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

func (s Status) String() string {
	if s < 0 || int(s) >= len(Statuses) {
		return Statuses[0]
	}
	return [...]string{}[s]
}

func (s Status) Index() int {
	return int(s)
}
