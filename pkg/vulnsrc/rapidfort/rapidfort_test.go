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
			baseOS:  ecosystem.Debian,
			osVer:   "12",
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
