package rootio

// RootIOFeed represents the Root.io patch feed structure (internal format)
type RootIOFeed struct {
	BaseOS  string             `json:"base_os"` // debian, ubuntu, alpine
	Version string             `json:"version"` // OS version (e.g., "11", "20.04", "3.20")
	Patches map[string][]Patch `json:"patches"` // package name -> patches
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

// Patch represents a single patch entry from Root.io
type Patch struct {
	VulnerabilityID string `json:"vulnerability_id"` // CVE-ID
	// VulnerableVersions contains constraint format (e.g., ">=1.2.3, <2.0.0")
	VulnerableVersions []string `json:"vulnerable_versions"`
	FixedVersion       string   `json:"fixed_version,omitempty"`
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
