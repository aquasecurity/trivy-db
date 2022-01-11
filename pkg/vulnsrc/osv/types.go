package osv

import "golang.org/x/vuln/osv"

// source: https://github.com/golang/vuln/blob/9d39a965865fd1d0030df18602433a01f679fd7d/osv/json.go
type Entry struct {
	// According to the specification, "summary" field is missing in the below struct.
	// https://ossf.github.io/osv-schema/
	Summary string `json:"summary"`

	osv.Entry
}
