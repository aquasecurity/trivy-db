package rootio

import "github.com/aquasecurity/trivy-db/pkg/types"

// Feed represents the Root.io patch feed structure (internal format)
type Feed struct {
	VulnerabilityID string
	PkgName         string
	Patch           types.Advisory
}

// RawFeed represents the actual Root.io API feed format
type RawFeed map[string][]RawDistroData

// RawDistroData represents distribution data from the API
type RawDistroData struct {
	DistroVersion string           `json:"distroversion"`
	Packages      []RawPackageData `json:"packages"`
}

// RawPackageData represents package data from the API
type RawPackageData struct {
	Pkg RawPackageInfo `json:"pkg"`
}

// RawPackageInfo represents package info from the API
type RawPackageInfo struct {
	Name string                `json:"name"`
	CVEs map[string]RawCVEInfo `json:"cves"`
}

// RawCVEInfo represents CVE info from the API
type RawCVEInfo struct {
	VulnerableRanges []string `json:"vulnerable_ranges"`
	FixedVersions    []string `json:"fixed_versions"`
	Severity         string   `json:"severity,omitempty"`
}
