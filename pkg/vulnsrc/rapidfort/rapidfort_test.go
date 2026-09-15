package rapidfort_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/rapidfort"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
)

func TestVulnSrc_Update(t *testing.T) {
	tests := []struct {
		name       string
		dir        string
		wantValues []vulnsrctest.WantValues
		noBuckets  [][]string
		wantErr    string
	}{
		{
			name: "happy path",
			dir:  filepath.Join("testdata", "happy"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{
						"data-source",
						"rapidfort ubuntu 20.04",
					},
					Value: types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "ubuntu",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2020-8169",
						"rapidfort ubuntu 20.04",
						"curl",
					},
					Value: types.Advisory{
						PatchedVersions:    []string{"7.68.0-1ubuntu2.1"},
						VulnerableVersions: []string{">=7.68.0, <7.68.0-1ubuntu2.1"},
						Severity:           types.SeverityHigh,
					},
				},
				{
					// Open vulnerability: no patched version
					Key: []string{
						"advisory-detail",
						"CVE-2021-22876",
						"rapidfort ubuntu 20.04",
						"curl",
					},
					Value: types.Advisory{
						VulnerableVersions: []string{">=7.68.0"},
						Severity:           types.SeverityMedium,
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2020-8169",
						"rapidfort",
					},
					Value: types.VulnerabilityDetail{
						Title:       "curl: partial password leak over DNS on HTTP redirect",
						Description: "curl 7.62.0 through 7.70.0 is vulnerable to an information disclosure vulnerability.",
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2021-22876",
						"rapidfort",
					},
					Value: types.VulnerabilityDetail{
						Title:       "curl: Automatic referer leaks credentials",
						Description: "curl does not strip off user credentials from the URL when automatically populating the Referer: HTTP request header field.",
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2020-8169",
					},
					Value: map[string]any{},
				},
				{
					Key: []string{
						"data-source",
						"rapidfort alpine 3.18",
					},
					Value: types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "alpine",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2023-5678",
						"rapidfort alpine 3.18",
						"libssl3",
					},
					Value: types.Advisory{
						PatchedVersions:    []string{"3.1.4-r1"},
						VulnerableVersions: []string{">=3.0.0, <3.1.4-r1"},
						Severity:           types.SeverityMedium,
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2023-5678",
						"rapidfort",
					},
					Value: types.VulnerabilityDetail{
						Title:       "openssl: X.400 address type confusion in X.509 GeneralName",
						Description: "There is a type confusion vulnerability relating to X.400 address processing inside an X.509 GeneralName.",
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2023-5678",
					},
					Value: map[string]any{},
				},
				{
					// Event with a fixed version but no introduced bound:
					// the vulnerable range is written as a bare "<fixed"
					Key: []string{
						"advisory-detail",
						"CVE-2024-0001",
						"rapidfort alpine 3.18",
						"libssl3",
					},
					Value: types.Advisory{
						PatchedVersions:    []string{"3.1.5-r0"},
						VulnerableVersions: []string{"<3.1.5-r0"},
						Severity:           types.SeverityLow,
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2024-0001",
						"rapidfort",
					},
					Value: types.VulnerabilityDetail{
						Title:       "openssl: hypothetical fix without a known introduced version",
						Description: "A hypothetical openssl vulnerability whose fixed build is known but the introduced version is not.",
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2024-0001",
					},
					Value: map[string]any{},
				},
				{
					Key: []string{
						"data-source",
						"rapidfort Red Hat 9",
					},
					Value: types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "redhat",
					},
				},
				{
					// RHEL ranges only — fc39 and rf ranges of the same CVE
					// land in their own buckets below.
					Key: []string{
						"advisory-detail",
						"CVE-2023-27536",
						"rapidfort Red Hat 9",
						"curl",
					},
					Value: types.Advisory{
						PatchedVersions:    []string{"7.76.1-26.el9_3.3"},
						VulnerableVersions: []string{">=7.76.1-14.el9, <7.76.1-26.el9_3.3"},
						Severity:           types.SeverityMedium,
					},
				},
				{
					Key: []string{
						"data-source",
						"rapidfort fedora 39",
					},
					Value: types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "fedora",
					},
				},
				{
					// The redhat and oracle feeds both carry an fc39 range for
					// this CVE, and both land in the shared fedora bucket. The
					// ranges differ, so they are unioned rather than letting the
					// last file walked overwrite the other. The identical fixed
					// version is de-duplicated.
					Key: []string{
						"advisory-detail",
						"CVE-2023-27536",
						"rapidfort fedora 39",
						"curl",
					},
					Value: types.Advisory{
						PatchedVersions: []string{"7.76.1-26.fc39"},
						VulnerableVersions: []string{
							"<7.76.1-26.fc39",
							">=7.76.1-14.fc39, <7.76.1-26.fc39",
						},
						Severity: types.SeverityMedium,
					},
				},
				{
					Key: []string{
						"data-source",
						"rapidfort Red Hat",
					},
					Value: types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "redhat",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2023-27536",
						"rapidfort Red Hat",
						"curl",
					},
					Value: types.Advisory{
						PatchedVersions:    []string{"7.76.1-26.rf"},
						VulnerableVersions: []string{">=7.76.1-14.rf, <7.76.1-26.rf"},
						Severity:           types.SeverityMedium,
					},
				},
				{
					// Open vulnerability: no patched version. The source entry
					// also carries a range without an identifier, which belongs
					// to the release the file lists it under — the same bucket
					// as the el9 range here.
					Key: []string{
						"advisory-detail",
						"CVE-2024-99999",
						"rapidfort Red Hat 9",
						"curl",
					},
					Value: types.Advisory{
						VulnerableVersions: []string{">=1.0", ">=7.76.1-14.el9"},
						Severity:           types.SeverityHigh,
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2023-27536",
						"rapidfort",
					},
					Value: types.VulnerabilityDetail{
						Title:       "curl: GSS delegation too eager connection re-use",
						Description: "An authentication bypass vulnerability exists in libcurl prior to v8.0.0 where it reuses a previously established GSS-negotiate connection.",
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2024-99999",
						"rapidfort",
					},
					Value: types.VulnerabilityDetail{
						Title:       "curl: hypothetical unfixed vulnerability",
						Description: "A hypothetical vulnerability in curl that has not yet been fixed.",
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2023-27536",
					},
					Value: map[string]any{},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2024-99999",
					},
					Value: map[string]any{},
				},
				// Oracle tags its releases "elN" like the RHEL it rebuilds, so its
				// feed splits the same way the redhat one does: elN to the versioned
				// Oracle buckets, fcNN to the shared fedora buckets asserted above,
				// and rf to an Oracle-scoped bucket.
				{
					Key: []string{
						"data-source",
						"rapidfort Oracle Linux 9",
					},
					Value: types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "oracle-oval",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2023-27536",
						"rapidfort Oracle Linux 9",
						"curl",
					},
					Value: types.Advisory{
						PatchedVersions:    []string{"7.76.1-26.el9_3.3"},
						VulnerableVersions: []string{">=7.76.1-14.el9, <7.76.1-26.el9_3.3"},
						Severity:           types.SeverityMedium,
					},
				},
				{
					// The el5 range is filed under a malformed top-level key
					// ("el5" where a bare "5" was meant). Splitting re-keys by
					// the range identifier, so the release still comes out as 5.
					Key: []string{
						"data-source",
						"rapidfort Oracle Linux 5",
					},
					Value: types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "oracle-oval",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2024-EL5KEY",
						"rapidfort Oracle Linux 5",
						"curl",
					},
					Value: types.Advisory{
						PatchedVersions:    []string{"7.19.7-54.el5"},
						VulnerableVersions: []string{"<7.19.7-54.el5"},
						Severity:           types.SeverityHigh,
					},
				},
				{
					// RapidFort's own rebuilds from the oracle feed: the feed's
					// ecosystem with the release dropped, kept apart from the
					// "rapidfort Red Hat" rebuild bucket the redhat feed writes.
					// The two hold different fixed versions for the same CVE and
					// package, which is exactly why they must not share.
					Key: []string{
						"data-source",
						"rapidfort Oracle Linux",
					},
					Value: types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "oracle-oval",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2023-27536",
						"rapidfort Oracle Linux",
						"curl",
					},
					Value: types.Advisory{
						PatchedVersions:    []string{"7.76.1-27.rf"},
						VulnerableVersions: []string{">=7.76.1-14.rf, <7.76.1-27.rf"},
						Severity:           types.SeverityMedium,
					},
				},
				// Alma tags its releases "elN" like the RHEL it rebuilds, so the
				// dist tag names the release while the feed's directory still names
				// the distribution.
				{
					Key: []string{
						"data-source",
						"rapidfort alma 9",
					},
					Value: types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "alma",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2023-38546",
						"rapidfort alma 9",
						"curl",
					},
					Value: types.Advisory{
						PatchedVersions:    []string{"7.76.1-29.el9_3.2"},
						VulnerableVersions: []string{">=7.76.1-26.el9, <7.76.1-29.el9_3.2"},
						Severity:           types.SeverityLow,
					},
				},
				{
					Key: []string{
						"data-source",
						"rapidfort alma",
					},
					Value: types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "alma",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2023-38546",
						"rapidfort alma",
						"curl",
					},
					Value: types.Advisory{
						PatchedVersions:    []string{"7.76.1-29.rf"},
						VulnerableVersions: []string{">=7.76.1-26.rf, <7.76.1-29.rf"},
						Severity:           types.SeverityLow,
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2023-38546",
						"rapidfort",
					},
					Value: types.VulnerabilityDetail{
						Title:       "curl: cookie injection with none file",
						Description: "libcurl can be tricked into injecting cookies into a running program when an application creates a new easy handle by duplicating an existing one.",
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2023-38546",
					},
					Value: map[string]any{},
				},
				// Rocky routes the same way alma does, from its own feed
				// directory and under a different RHEL major.
				{
					Key: []string{
						"data-source",
						"rapidfort rocky 8",
					},
					Value: types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "rocky",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2024-2398",
						"rapidfort rocky 8",
						"curl",
					},
					Value: types.Advisory{
						PatchedVersions:    []string{"7.61.1-34.el8_9.3"},
						VulnerableVersions: []string{">=7.61.1-30.el8, <7.61.1-34.el8_9.3"},
						Severity:           types.SeverityMedium,
					},
				},
				{
					Key: []string{
						"data-source",
						"rapidfort rocky",
					},
					Value: types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "rocky",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2024-2398",
						"rapidfort rocky",
						"curl",
					},
					Value: types.Advisory{
						PatchedVersions:    []string{"7.61.1-34.rf"},
						VulnerableVersions: []string{">=7.61.1-30.rf, <7.61.1-34.rf"},
						Severity:           types.SeverityMedium,
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2024-2398",
						"rapidfort",
					},
					Value: types.VulnerabilityDetail{
						Title:       "curl: HTTP/2 push headers memory leak",
						Description: "When an application tells libcurl it wants to allow HTTP/2 server push, the amount of received headers for the push can exhaust memory.",
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2024-2398",
					},
					Value: map[string]any{},
				},
				// Amazon Linux tags its releases "amzn2"/"amzn2023" rather than
				// elN, and the feed lists each under its own version key.
				{
					Key: []string{
						"data-source",
						"rapidfort amazon linux 2",
					},
					Value: types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "amazon",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2023-46218",
						"rapidfort amazon linux 2",
						"curl",
					},
					Value: types.Advisory{
						PatchedVersions:    []string{"8.3.0-1.amzn2.0.2"},
						VulnerableVersions: []string{">=7.61.1-22.amzn2, <8.3.0-1.amzn2.0.2"},
						Severity:           types.SeverityMedium,
					},
				},
				{
					Key: []string{
						"data-source",
						"rapidfort amazon linux 2023",
					},
					Value: types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "amazon",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2023-46218",
						"rapidfort amazon linux 2023",
						"curl",
					},
					Value: types.Advisory{
						PatchedVersions:    []string{"8.5.0-1.amzn2023"},
						VulnerableVersions: []string{">=8.4.0-1.amzn2023, <8.5.0-1.amzn2023"},
						Severity:           types.SeverityMedium,
					},
				},
				{
					Key: []string{
						"data-source",
						"rapidfort amazon linux",
					},
					Value: types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "amazon",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2023-46218",
						"rapidfort amazon linux",
						"curl",
					},
					Value: types.Advisory{
						PatchedVersions:    []string{"8.5.0-1.rf"},
						VulnerableVersions: []string{">=8.4.0-1.rf, <8.5.0-1.rf"},
						Severity:           types.SeverityMedium,
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2023-46218",
						"rapidfort",
					},
					Value: types.VulnerabilityDetail{
						Title:       "curl: information disclosure by exploiting a mixed case flaw",
						Description: "A malicious HTTP server can set \"super cookies\" that are passed back to more origins than what is otherwise allowed or possible.",
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2023-46218",
					},
					Value: map[string]any{},
				},
				// The debian feed is dpkg like ubuntu: its own packages are
				// tagged by ecosystem name, its rebuilds by "rf".
				{
					Key: []string{
						"data-source",
						"rapidfort debian 12",
					},
					Value: types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "debian",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2023-38545",
						"rapidfort debian 12",
						"curl",
					},
					Value: types.Advisory{
						PatchedVersions:    []string{"7.88.1-10+deb12u5"},
						VulnerableVersions: []string{">=7.88.1-10, <7.88.1-10+deb12u5"},
						Severity:           types.SeverityHigh,
					},
				},
				{
					Key: []string{
						"data-source",
						"rapidfort debian",
					},
					Value: types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "debian",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2023-38545",
						"rapidfort debian",
						"curl",
					},
					Value: types.Advisory{
						PatchedVersions:    []string{"7.88.1-12.rf1"},
						VulnerableVersions: []string{">=7.88.1-10.rf1, <7.88.1-12.rf1"},
						Severity:           types.SeverityHigh,
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2023-38545",
						"rapidfort",
					},
					Value: types.VulnerabilityDetail{
						Title:       "curl: SOCKS5 heap buffer overflow",
						Description: "curl overflows a heap based buffer in the SOCKS5 proxy handshake when the hostname is longer than 255 bytes.",
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2023-38545",
					},
					Value: map[string]any{},
				},
			},
			noBuckets: [][]string{
				// The malformed "el5" top-level key is never used as a release:
				// the range identifier decides the bucket, so no bucket is keyed
				// on the raw key.
				{"advisory-detail", "CVE-2024-EL5KEY", "rapidfort Oracle Linux el5"},
			},
		},
		{
			// A single source file that declares multiple distro versions must
			// fan out into one platform bucket per populated version, and an
			// empty version must not produce phantom entries.
			name: "multi-version file - each version becomes its own platform bucket",
			dir:  filepath.Join("testdata", "multiversion"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"data-source", "rapidfort ubuntu 20.04"},
					Value: types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "ubuntu",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2020-8169",
						"rapidfort ubuntu 20.04",
						"curl",
					},
					Value: types.Advisory{
						PatchedVersions:    []string{"7.68.0-1ubuntu2.1"},
						VulnerableVersions: []string{">=7.68.0, <7.68.0-1ubuntu2.1"},
						Severity:           types.SeverityHigh,
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2020-8169",
						"rapidfort",
					},
					Value: types.VulnerabilityDetail{
						Title:       "curl: partial password leak over DNS on HTTP redirect",
						Description: "curl 7.62.0 through 7.70.0 is vulnerable to an information disclosure vulnerability.",
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2020-8169"},
					Value: map[string]any{},
				},
				{
					Key: []string{"data-source", "rapidfort ubuntu 22.04"},
					Value: types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "ubuntu",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2023-38039",
						"rapidfort ubuntu 22.04",
						"curl",
					},
					Value: types.Advisory{
						PatchedVersions:    []string{"7.81.0-1ubuntu1.14"},
						VulnerableVersions: []string{">=7.81.0, <7.81.0-1ubuntu1.14"},
						Severity:           types.SeverityMedium,
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2023-38039",
						"rapidfort",
					},
					Value: types.VulnerabilityDetail{
						Title:       "curl: out of heap memory issue due to missing limit on header quantity",
						Description: "When curl retrieves an HTTP response, it stores the incoming headers so that they can be accessed later via the libcurl headers API.",
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2023-38039"},
					Value: map[string]any{},
				},
				// The redhat source file lists the same fc39 range under two
				// RHEL major keys — dedupe must collapse it to a single fedora
				// bucket entry.
				{
					Key: []string{"data-source", "rapidfort Red Hat 8"},
					Value: types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "redhat",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2023-27536",
						"rapidfort Red Hat 8",
						"curl",
					},
					Value: types.Advisory{
						VulnerableVersions: []string{">=7.61.1-14.el8"},
						Severity:           types.SeverityMedium,
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2023-27536",
						"rapidfort Red Hat 9",
						"curl",
					},
					Value: types.Advisory{
						PatchedVersions:    []string{"7.76.1-26.el9_3.3"},
						VulnerableVersions: []string{">=7.76.1-14.el9, <7.76.1-26.el9_3.3"},
						Severity:           types.SeverityMedium,
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2023-27536",
						"rapidfort fedora 39",
						"curl",
					},
					Value: types.Advisory{
						PatchedVersions:    []string{"7.76.1-26.fc39"},
						VulnerableVersions: []string{">=7.76.1-14.fc39, <7.76.1-26.fc39"},
						Severity:           types.SeverityMedium,
					},
				},
			},
			// A non-numeric identifier version (e.g. "fcrawhide") is skipped
			// rather than turned into a bogus bucket name.
			noBuckets: [][]string{
				{"advisory-detail", "CVE-2023-27536", "rapidfort fedora rawhide"},
			},
		},
		{
			// Separate buckets keep a plain-ubuntu package from matching the rebuild range.
			name: "ubuntu split - rf and ubuntu ranges land in separate buckets",
			dir:  filepath.Join("testdata", "split_ubuntu"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"data-source", "rapidfort ubuntu 22.04"},
					Value: types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "ubuntu",
					},
				},
				{
					Key: []string{"data-source", "rapidfort ubuntu"},
					Value: types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "ubuntu",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2025-69648",
						"rapidfort ubuntu 22.04",
						"rf-binutils",
					},
					Value: types.Advisory{
						PatchedVersions:    []string{"0:2.46-1ubuntu1"},
						VulnerableVersions: []string{">=0:2.42-4ubuntu2.10, <0:2.46-1ubuntu1"},
						Severity:           types.SeverityMedium,
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2025-69648",
						"rapidfort ubuntu",
						"rf-binutils",
					},
					Value: types.Advisory{
						PatchedVersions:    []string{"0:2.46-10rfubu"},
						VulnerableVersions: []string{"<0:2.46-10rfubu"},
						Severity:           types.SeverityMedium,
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2025-69648",
						"rapidfort",
					},
					Value: types.VulnerabilityDetail{
						Title:       "binutils readelf DoS",
						Description: "GNU Binutils readelf contains a denial-of-service vulnerability when processing crafted DWARF data.",
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2025-69648"},
					Value: map[string]any{},
				},
			},
		},
		{
			// The feed lists one event per historical rebuild, all with the same
			// fix, so the fixed version must be stored once while every range is
			// kept.
			name: "repeated fix - PatchedVersions holds one entry per distinct fix",
			dir:  filepath.Join("testdata", "repeated_fix"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"data-source", "rapidfort ubuntu"},
					Value: types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "ubuntu",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2026-9076",
						"rapidfort ubuntu",
						"rf-openssl",
					},
					Value: types.Advisory{
						PatchedVersions: []string{"0:3.5.7-10rfubu+rf.0"},
						VulnerableVersions: []string{
							">=0:3.0.13-1rfubuntu3.1~rf.1, <0:3.5.7-10rfubu+rf.0",
							">=0:3.0.14-0rfubu3.1+rf.2, <0:3.5.7-10rfubu+rf.0",
							">=0:3.0.14-0rfubuntu3.1+rf.1, <0:3.5.7-10rfubu+rf.0",
						},
						Severity: types.SeverityLow,
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"CVE-2026-9076",
						"rapidfort",
					},
					Value: types.VulnerabilityDetail{
						Title:       "Issue summary: When CMS password-based decryption (RFC 3211 / PWR ...",
						Description: "Issue summary: When CMS password-based decryption (RFC 3211 / PWRI key unwrap)\nprocesses attacker-supplied CMS data, an attacker-chosen stream-mode KEK\ncipher can trigger a heap out-of-bounds read.",
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2026-9076"},
					Value: map[string]any{},
				},
			},
		},
		{
			// A misconfigured cache that produces zero entries must surface as
			// an error, not ship an empty integration.
			name:    "malformed path - json directly under OS/ triggers empty-parse error",
			dir:     filepath.Join("testdata", "malformed_path"),
			wantErr: "no RapidFort advisories to save",
		},
		{
			name:    "empty parse (all unsupported OSes) returns error",
			dir:     filepath.Join("testdata", "unsupported_os"),
			wantErr: "no RapidFort advisories to save",
		},
		{
			// A bare dist tag ("el") names no release and an identifier from a
			// distribution Trivy doesn't dispatch to ("sles15") names no bucket,
			// so both ranges are dropped instead of falling back to a bucket
			// they don't belong to — here that leaves the file with no entries.
			name:    "unusable identifiers are dropped, not guessed",
			dir:     filepath.Join("testdata", "unusable_identifier"),
			wantErr: "no RapidFort advisories to save",
		},
		{
			name:    "sad path - invalid JSON",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "json decode error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := rapidfort.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				NoBuckets:  tt.noBuckets,
				WantErr:    tt.wantErr,
			})
		})
	}
}

func TestVulnSrc_Get(t *testing.T) {
	tests := []struct {
		name     string
		baseOS   ecosystem.Type
		osVer    string
		pkgName  string
		fixtures []string
		want     []types.Advisory
		wantErr  string
	}{
		{
			name:    "ubuntu advisory found",
			baseOS:  ecosystem.Ubuntu,
			osVer:   "20.04",
			pkgName: "curl",
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2020-8169",
					VulnerableVersions: []string{">=7.68.0, <7.68.0-1ubuntu2.1"},
					PatchedVersions:    []string{"7.68.0-1ubuntu2.1"},
					Severity:           types.SeverityHigh,
					DataSource: &types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "ubuntu",
					},
				},
			},
		},
		{
			name:    "alpine advisory found",
			baseOS:  ecosystem.Alpine,
			osVer:   "3.18",
			pkgName: "libssl3",
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2023-5678",
					VulnerableVersions: []string{">=3.0.0, <3.1.4-r1"},
					PatchedVersions:    []string{"3.1.4-r1"},
					Severity:           types.SeverityMedium,
					DataSource: &types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "alpine",
					},
				},
			},
		},
		{
			name:    "redhat advisory found",
			baseOS:  ecosystem.RedHat,
			osVer:   "9",
			pkgName: "curl",
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2023-27536",
					VulnerableVersions: []string{">=7.76.1-14.el9, <7.76.1-26.el9_3.3"},
					PatchedVersions:    []string{"7.76.1-26.el9_3.3"},
					Severity:           types.SeverityMedium,
					DataSource: &types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "redhat",
					},
				},
				{
					VulnerabilityID:    "CVE-2024-99999",
					VulnerableVersions: []string{">=7.76.1-14.el9"},
					Severity:           types.SeverityHigh,
					DataSource: &types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "redhat",
					},
				},
			},
		},
		{
			name:    "fedora advisory found",
			baseOS:  ecosystem.Fedora,
			osVer:   "39",
			pkgName: "curl",
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2023-27536",
					VulnerableVersions: []string{">=7.76.1-14.fc39, <7.76.1-26.fc39"},
					PatchedVersions:    []string{"7.76.1-26.fc39"},
					Severity:           types.SeverityMedium,
					DataSource: &types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "fedora",
					},
				},
			},
		},
		{
			name:    "rf advisory found",
			baseOS:  ecosystem.RedHat,
			osVer:   "",
			pkgName: "curl",
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2023-27536",
					VulnerableVersions: []string{">=7.76.1-14.rf, <7.76.1-26.rf"},
					PatchedVersions:    []string{"7.76.1-26.rf"},
					Severity:           types.SeverityMedium,
					DataSource: &types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "redhat",
					},
				},
			},
		},
		{
			name:    "oracle advisory found",
			baseOS:  ecosystem.OracleLinux,
			osVer:   "9",
			pkgName: "curl",
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2023-27536",
					VulnerableVersions: []string{">=7.76.1-14.el9, <7.76.1-26.el9_3.3"},
					PatchedVersions:    []string{"7.76.1-26.el9_3.3"},
					Severity:           types.SeverityMedium,
					DataSource: &types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "oracle-oval",
					},
				},
			},
		},
		{
			// The oracle feed's rf rebuilds get their own bucket
			// ("rapidfort Oracle Linux"), separate from the redhat feed's
			// ("rapidfort Red Hat"), which the empty release selects. The
			// fixture holds a different fixed version in each, so 7.76.1-27.rf
			// shows which one the lookup landed in.
			name:    "oracle rf advisory found",
			baseOS:  ecosystem.OracleLinux,
			osVer:   "",
			pkgName: "curl",
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2023-27536",
					VulnerableVersions: []string{">=7.76.1-14.rf, <7.76.1-27.rf"},
					PatchedVersions:    []string{"7.76.1-27.rf"},
					Severity:           types.SeverityMedium,
					DataSource: &types.DataSource{
						ID:     vulnerability.RapidFort,
						Name:   "RapidFort Security Advisories",
						URL:    "https://github.com/rapidfort/security-advisories",
						BaseID: "oracle-oval",
					},
				},
			},
		},
		{
			name:    "no advisory for package",
			baseOS:  ecosystem.Ubuntu,
			osVer:   "22.04",
			pkgName: "curl",
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			want: nil,
		},
		{
			// RapidFort dispatches to a fixed set of base OSes, so a getter built
			// for any other one has no bucket to read and must say so rather than
			// report the package as clean.
			name:    "sad path - base OS RapidFort doesn't dispatch to",
			baseOS:  ecosystem.PhotonOS,
			osVer:   "5.0",
			pkgName: "curl",
			fixtures: []string{
				"testdata/fixtures/happy.yaml",
				"testdata/fixtures/data-source.yaml",
			},
			wantErr: "unsupported base ecosystem",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := rapidfort.NewVulnSrcGetter(tt.baseOS)
			vulnsrctest.TestGet(t, vs, vulnsrctest.TestGetArgs{
				Fixtures:   tt.fixtures,
				WantValues: tt.want,
				GetParams: db.GetParams{
					Release: tt.osVer,
					PkgName: tt.pkgName,
				},
				WantErr: tt.wantErr,
			})
		})
	}
}

func TestVulnSrc_Name(t *testing.T) {
	vs := rapidfort.NewVulnSrc()
	assert.Equal(t, vulnerability.RapidFort, vs.Name())
}
