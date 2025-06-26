package rootio

import "github.com/aquasecurity/trivy-db/pkg/types"

// RootIOFeed represents the Root.io patch feed structure (internal format)
type RootIOFeed struct {
	VulnerabilityID string
	PkgName         string
	Patch           types.Advisory
}

// RawRootIOFeed represents the actual Root.io API feed format
type RawRootIOFeed struct {
	Alpine []RawDistroData `json:"alpine,omitempty"`
	Debian []RawDistroData `json:"debian,omitempty"`
	Ubuntu []RawDistroData `json:"ubuntu,omitempty"`
}

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
}

// OSType represents supported base operating systems
type OSType string

const (
	Debian OSType = "debian"
	Ubuntu OSType = "ubuntu"
	Alpine OSType = "alpine"
)

// IsValidOSType checks if the given OS type is supported
func IsValidOSType(osType string) bool {
	switch OSType(osType) {
	case Debian, Ubuntu, Alpine:
		return true
	default:
		return false
	}
}
