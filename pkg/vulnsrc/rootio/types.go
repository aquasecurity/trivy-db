package rootio

import "github.com/aquasecurity/trivy-db/pkg/types"

// Feed represents the Root.io patch feed structure (internal format)
type Feed struct {
	VulnerabilityID string
	PkgName         string
	Patch           types.Advisory
}

// RawFeed represents the actual Root.io API feed format for OS packages
type RawFeed map[string][]RawDistroData

// RawDistroData represents distribution data from the API
// Supports both old format (distroversion field) and new format (distro object)
type RawDistroData struct {
	DistroVersion string           `json:"distroversion,omitempty"` // Old format
	Distro        *RawDistroInfo   `json:"distro,omitempty"`        // New format
	Packages      []RawPackageData `json:"packages"`
}

// RawDistroInfo represents distro metadata from the API
type RawDistroInfo struct {
	Name              string `json:"name"`
	Latest            string `json:"latest"`
	MinFixedVersion   string `json:"min_fixed_version"`
	MaxFixedVersion   string `json:"max_fixed_version"`
	MinUnfixedVersion string `json:"min_unfixed_version"`
	MaxUnfixedVersion string `json:"max_unfixed_version"`
}

// RawPackageData represents package data from the API
// Supports both old format (pkg nested object) and new format (direct fields)
type RawPackageData struct {
	// New format fields
	Name       string                `json:"name,omitempty"`
	MinVersion string                `json:"min_version,omitempty"`
	MaxVersion string                `json:"max_version,omitempty"`
	CVEs       map[string]RawCVEInfo `json:"cves,omitempty"`
	// Old format field
	Pkg *RawPackageInfo `json:"pkg,omitempty"`
}

// RawPackageInfo represents package info from the API (old format)
type RawPackageInfo struct {
	Name string                `json:"name"`
	CVEs map[string]RawCVEInfo `json:"cves"`
}

// RawCVEInfo represents CVE info from the API
type RawCVEInfo struct {
	VulnerableRanges []string `json:"vulnerable_ranges"`
	FixedVersions    []string `json:"fixed_versions"`
}

// RawLanguagePackage represents a language package with its vulnerabilities
type RawLanguagePackage struct {
	Name string                `json:"name"`
	CVEs map[string]RawCVEInfo `json:"cves"`
}

// RawAppFeed represents the combined app feed format containing all language ecosystems
type RawAppFeed map[string][]RawLanguagePackage
