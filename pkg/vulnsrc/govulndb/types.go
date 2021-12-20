package govulndb

import "golang.org/x/vuln/osv"

// source: https://github.com/golang/vulndb/blob/e0c00fae09e687ec6febda47ae3bc7552fc7b988/osv/json.go#L125
type Entry struct {
	// We need to add this field on our end until the following issue will be addressed.
	// https://github.com/golang/go/issues/50006
	Module string `json:"module"`

	osv.Entry
}
