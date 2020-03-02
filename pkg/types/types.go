package types

import (
	"fmt"
	"time"

	"github.com/fatih/color"
)

type Severity int

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
	ID          string   `json:",omitempty"` // e.g. CVE-2019-8331, OSVDB-104365
	CvssScore   float64  `json:",omitempty"`
	CvssScoreV3 float64  `json:",omitempty"`
	Severity    Severity `json:",omitempty"`
	SeverityV3  Severity `json:",omitempty"`
	References  []string `json:",omitempty"`
	Title       string   `json:",omitempty"`
	Description string   `json:",omitempty"`
}

type Advisory struct {
	VulnerabilityID string `json:",omitempty"`
	FixedVersion    string `json:",omitempty"`
}

type Vulnerability struct {
	Title       string   `json:",omitempty"`
	Description string   `json:",omitempty"`
	Severity    string   `json:",omitempty"`
	References  []string `json:",omitempty"`
}

type VulnSrc interface {
	Update(dir string) (err error)
	Get(release string, pkgName string) (advisories []Advisory, err error)
}
