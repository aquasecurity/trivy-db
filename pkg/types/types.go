package types

import (
	"fmt"
	"time"

	"github.com/fatih/color"
)

type Severity int

type VendorSeverity map[string]Severity

type CVSS struct {
	V2Vector string  `json:"V2Vector,omitempty"`
	V3Vector string  `json:"V3Vector,omitempty"`
	V2Score  float64 `json:"V2Score,omitempty"`
	V3Score  float64 `json:"V3Score,omitempty"`
}

type CVSSVector struct {
	V2 string `json:"v2,omitempty"`
	V3 string `json:"v3,omitempty"`
}

type VendorCVSS map[string]CVSS

const (
	SeverityUnknown Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var (
	SeverityNames = []string{
		"UNKNOWN",
		"LOW",
		"MEDIUM",
		"HIGH",
		"CRITICAL",
	}
	SeverityColor = []func(a ...interface{}) string{
		color.New(color.FgCyan).SprintFunc(),
		color.New(color.FgBlue).SprintFunc(),
		color.New(color.FgYellow).SprintFunc(),
		color.New(color.FgHiRed).SprintFunc(),
		color.New(color.FgRed).SprintFunc(),
	}
)

func NewSeverity(severity string) (Severity, error) {
	for i, name := range SeverityNames {
		if severity == name {
			return Severity(i), nil
		}
	}
	return SeverityUnknown, fmt.Errorf("unknown severity: %s", severity)
}

func CompareSeverityString(sev1, sev2 string) int {
	s1, _ := NewSeverity(sev1)
	s2, _ := NewSeverity(sev2)
	return int(s2) - int(s1)
}

func ColorizeSeverity(severity string) string {
	for i, name := range SeverityNames {
		if severity == name {
			return SeverityColor[i](severity)
		}
	}
	return color.New(color.FgBlue).SprintFunc()(severity)
}

func (s Severity) String() string {
	return SeverityNames[s]
}

type LastUpdated struct {
	Date time.Time
}
type VulnerabilityDetail struct {
	ID               string     `json:",omitempty"` // e.g. CVE-2019-8331, OSVDB-104365
	CvssScore        float64    `json:",omitempty"`
	CvssVector       string     `json:",omitempty"`
	CvssScoreV3      float64    `json:",omitempty"`
	CvssVectorV3     string     `json:",omitempty"`
	Severity         Severity   `json:",omitempty"`
	SeverityV3       Severity   `json:",omitempty"`
	CweIDs           []string   `json:",omitempty"` // e.g. CWE-78, CWE-89
	References       []string   `json:",omitempty"`
	Title            string     `json:",omitempty"`
	Description      string     `json:",omitempty"`
	PublishedDate    *time.Time `json:",omitempty"`
	LastModifiedDate *time.Time `json:",omitempty"`
}

type AdvisoryDetail struct {
	PlatformName string
	PackageName  string
	AdvisoryItem interface{}
}

type Advisory struct {
	VulnerabilityID string `json:",omitempty"`

	// for os package
	FixedVersion string `json:",omitempty"`

	// for library
	// Some advisories provide VulnerableVersions only, others provide PatchedVersions and UnaffectedVersions
	VulnerableVersions []string `json:",omitempty"`
	PatchedVersions    []string `json:",omitempty"`
	UnaffectedVersions []string `json:",omitempty"`
}

type Vulnerability struct {
	Title            string         `json:",omitempty"`
	Description      string         `json:",omitempty"`
	Severity         string         `json:",omitempty"` // Selected from VendorSeverity, depending on a scan target
	CweIDs           []string       `json:",omitempty"` // e.g. CWE-78, CWE-89
	VendorSeverity   VendorSeverity `json:",omitempty"`
	CVSS             VendorCVSS     `json:",omitempty"`
	References       []string       `json:",omitempty"`
	PublishedDate    *time.Time     `json:",omitempty"`
	LastModifiedDate *time.Time     `json:",omitempty"`
}

type VulnSrc interface {
	Update(dir string) (err error)
	Get(release string, pkgName string) (advisories []Advisory, err error)
}
