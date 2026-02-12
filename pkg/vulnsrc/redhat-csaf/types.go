package redhatcsaf

import (
	"encoding/json"
	"slices"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/package-url/packageurl-go"

	"github.com/aquasecurity/trivy-db/pkg/types"
)

type Package struct {
	Module string
	Name   string
}

type VulnerabilityID string

type Bucket struct {
	Package
	VulnerabilityID
}

// RawEntry represents a single unprocessed entry of vulnerability-related information
// for a specific package, obtained directly from a CSAF VEX.
type RawEntry struct {
	FixedVersion string
	Status       types.Status
	Severity     types.Severity
	Arch         string
	CPE          csaf.CPE
	Alias        VulnerabilityID // CVE-ID
}

type RawEntries []RawEntry

type Product struct {
	Module  string
	Package packageurl.PackageURL
	Stream  csaf.CPE
}

// Advisory is the final structure that will be stored in the database.
// It holds aggregated Entries to reduce database size.
type Advisory struct {
	Entries []Entry `json:",omitempty"`
}

// Entry holds the unique advisory information per platform.
type Entry struct {
	FixedVersion string       `json:",omitempty"`
	CVEs         []CVEEntry   `json:"Cves"`
	Arches       []string     `json:",omitempty"`
	Status       types.Status `json:"-"`

	// AffectedCPEList is used during parsing, then converted to indices for storage.
	AffectedCPEList []string `json:"-"`
	// AffectedCPEIndices stores CPE indices for efficient matching at scan time.
	AffectedCPEIndices []int `json:"Affected,omitempty"`

	// Custom is basically for extensibility and is not supposed to be used in OSS
	Custom any `json:",omitempty"`
}

// MarshalJSON customizes JSON marshaling for Entry.
// types.Status has its own MarshalJSON that serializes to a string (e.g., "affected"),
// but storing strings increases database size. This method serializes Status as an int
// to reduce storage overhead.
func (e Entry) MarshalJSON() ([]byte, error) {
	type Alias Entry
	return json.Marshal(&struct {
		Status int `json:"Status,omitempty"`
		Alias
	}{
		Status: int(e.Status),
		Alias:  Alias(e),
	})
}

// TODO: UnmarshalJSON is not currently needed because Get() delegates to redhat-oval.
// When redhat-oval is removed and Get() is implemented in this package, uncomment this method.
//
// func (e *Entry) UnmarshalJSON(data []byte) error {
// 	type Alias Entry
// 	aux := &struct {
// 		Status int `json:"Status,omitempty"`
// 		*Alias
// 	}{
// 		Alias: (*Alias)(e),
// 	}
// 	if err := json.Unmarshal(data, &aux); err != nil {
// 		return err
// 	}
// 	e.Status = types.Status(aux.Status)
// 	return nil
// }

type Entries []Entry

func (e Entries) Len() int {
	return len(e)
}

func (e Entries) Less(i, j int) bool {
	switch {
	case e[i].FixedVersion != e[j].FixedVersion:
		return e[i].FixedVersion < e[j].FixedVersion
	case e[i].Status != e[j].Status:
		return int(e[i].Status) < int(e[j].Status)
	case !slices.Equal(e[i].CVEs, e[j].CVEs):
		return encodeCVEs(e[i].CVEs) < encodeCVEs(e[j].CVEs)
	case !slices.Equal(e[i].Arches, e[j].Arches):
		return slices.Compare(e[i].Arches, e[j].Arches) < 0
	case !slices.Equal(e[i].AffectedCPEIndices, e[j].AffectedCPEIndices):
		return slices.Compare(e[i].AffectedCPEIndices, e[j].AffectedCPEIndices) < 0
	}
	return false
}

func (e Entries) Swap(i, j int) {
	e[i], e[j] = e[j], e[i]
}

type CVEEntry struct {
	ID string `json:",omitempty"`

	// Severity may differ depending on platform even though the advisories resolve the same RawEntry-ID.
	Severity types.Severity `json:",omitempty"`
}
