package susecsaf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
)

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func TestVulnSrc_Update(t *testing.T) {
	tests := []struct {
		name       string
		dir        string
		dist       Distribution
		wantValues []vulnsrctest.WantValues
		noBuckets  [][]string
		wantErr    string
	}{
		{
			name: "happy path with SUSE Enterprise Linux",
			dir:  filepath.Join("testdata", "happy", "SUSE Enterprise Linux"),
			dist: SUSEEnterpriseLinux,
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"data-source", "SUSE Linux Enterprise 15.1"},
					Value: types.DataSource{
						ID:   vulnerability.SuseCSAF,
						Name: "SUSE CSAF",
						URL:  "https://ftp.suse.com/pub/projects/security/csaf/",
					},
				},
				{
					Key: []string{
						"advisory-detail", "SUSE-SU-2019:0048-2", "SUSE Linux Enterprise 15.1", "helm-mirror",
					},
					Value: types.Advisory{
						FixedVersion: "0.2.1-1.7.1",
					},
				},
				{
					Key: []string{"vulnerability-detail", "SUSE-SU-2019:0048-2", "suse-csaf"},
					Value: types.VulnerabilityDetail{
						Title:       "Security update for helm-mirror",
						Description: "This update for helm-mirror to version 0.2.1 fixes the following issues:\n\n\nSecurity issues fixed:\n\n- CVE-2018-16873: Fixed a remote command execution (bsc#1118897)\n- CVE-2018-16874: Fixed a directory traversal in 'go get' via curly braces in import path (bsc#1118898)\n- CVE-2018-16875: Fixed a CPU denial of service (bsc#1118899)\n\nNon-security issue fixed:\n\n- Update to v0.2.1 (bsc#1120762)\n- Include helm-mirror into the containers module (bsc#1116182)\n",
						References: []string{
							"https://www.suse.com/support/security/rating/",
							"https://ftp.suse.com/pub/projects/security/csaf/suse-su-2019_0048-2.json",
							"https://www.suse.com/support/update/announcement/2019/suse-su-20190048-2/",
							"https://lists.suse.com/pipermail/sle-security-updates/2019-July/005660.html",
							"https://bugzilla.suse.com/1116182",
							"https://bugzilla.suse.com/1118897",
							"https://bugzilla.suse.com/1118898",
							"https://bugzilla.suse.com/1118899",
							"https://bugzilla.suse.com/1120762",
							"https://www.suse.com/security/cve/CVE-2018-16873/",
							"https://www.suse.com/security/cve/CVE-2018-16874/",
							"https://www.suse.com/security/cve/CVE-2018-16875/",
						},
						Severity: types.SeverityHigh,
					},
				},
				{
					Key:   []string{"vulnerability-id", "SUSE-SU-2019:0048-2"},
					Value: map[string]any{},
				},
			},
		},
		{
			// The document carries values that the csaf package rejects while decoding:
			// CPEs with unescaped "," and "+" in product_tree.branches (as found in the live SUSE feed),
			// and an invalid language, tracking status, CVE ID, CVSS vector and remediation category in fields that trivy-db doesn't read.
			// It also checks that:
			// - arches are collapsed into one package and the zero epoch is dropped;
			// - the product ID is taken from full_product_name, even when it isn't "<platform>:<reference>";
			// - products missing from product_status are skipped;
			// - references without a URL are skipped.
			name: "happy path with non-conformant document",
			dir:  filepath.Join("testdata", "happy", "non-conformant document"),
			dist: SUSEEnterpriseLinux,
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"data-source", "SUSE Linux Enterprise 15.1"},
					Value: types.DataSource{
						ID:   vulnerability.SuseCSAF,
						Name: "SUSE CSAF",
						URL:  "https://ftp.suse.com/pub/projects/security/csaf/",
					},
				},
				{
					Key: []string{
						"advisory-detail", "SUSE-SU-2019:0048-2", "SUSE Linux Enterprise 15.1", "helm-mirror",
					},
					Value: types.Advisory{
						FixedVersion: "0.2.1-1.7.1",
					},
				},
				{
					Key: []string{
						"advisory-detail", "SUSE-SU-2019:0048-2", "SUSE Linux Enterprise 15.1", "epoch-pkg",
					},
					Value: types.Advisory{
						FixedVersion: "2:1.0-1.1",
					},
				},
				{
					Key: []string{"vulnerability-detail", "SUSE-SU-2019:0048-2", "suse-csaf"},
					Value: types.VulnerabilityDetail{
						Title:       "Security update for helm-mirror",
						Description: "details",
						References:  []string{"https://example.com/advisory"},
						Severity:    types.SeverityHigh,
					},
				},
				{
					Key:   []string{"vulnerability-id", "SUSE-SU-2019:0048-2"},
					Value: map[string]any{},
				},
			},
			noBuckets: [][]string{
				// "not-listed" is the only package for SLE 12.5, and it isn't in product_status.
				{"advisory-detail", "SUSE-SU-2019:0048-2", "SUSE Linux Enterprise 12.5"},
			},
		},
		{
			// Some advisories have no vulnerabilities section (e.g. SUSE-SU-2022:1714-1):
			// every relationship is used and the severity falls back to document.aggregate_severity.
			name: "happy path without vulnerabilities",
			dir:  filepath.Join("testdata", "happy", "no vulnerabilities"),
			dist: SUSEEnterpriseLinux,
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"data-source", "SUSE Linux Enterprise 12.5"},
					Value: types.DataSource{
						ID:   vulnerability.SuseCSAF,
						Name: "SUSE CSAF",
						URL:  "https://ftp.suse.com/pub/projects/security/csaf/",
					},
				},
				{
					Key: []string{
						"advisory-detail", "SUSE-SU-2022:1714-1", "SUSE Linux Enterprise 12.5", "php72",
					},
					Value: types.Advisory{
						FixedVersion: "7.2.5-1.81.1",
					},
				},
				{
					Key: []string{"vulnerability-detail", "SUSE-SU-2022:1714-1", "suse-csaf"},
					Value: types.VulnerabilityDetail{
						Title:    "Security update for php72",
						Severity: types.SeverityMedium,
					},
				},
				{
					Key:   []string{"vulnerability-id", "SUSE-SU-2022:1714-1"},
					Value: map[string]any{},
				},
			},
		},
		{
			name:    "sad path (dir doesn't exist)",
			dir:     filepath.Join("testdata", "badPath"),
			dist:    OpenSUSE,
			wantErr: "no such file or directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := NewVulnSrc(tt.dist)
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
		fixtures []string
		version  string
		pkgName  string
		dist     Distribution
		want     []types.Advisory
		wantErr  string
	}{
		{
			name:     "happy path",
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			version:  "13.1",
			pkgName:  "bind",
			dist:     OpenSUSE,
			want: []types.Advisory{
				{
					VulnerabilityID: "openSUSE-SU-2019:0003-1",
					FixedVersion:    "1.3.29-bp150.2.12.1",
				},
			},
		},
		{
			name:     "no advisories are returned",
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			version:  "15.1",
			pkgName:  "bind",
			dist:     OpenSUSE,
			want:     nil,
		},
		{
			name:     "GetAdvisories returns an error",
			fixtures: []string{"testdata/fixtures/sad.yaml"},
			version:  "13.1",
			pkgName:  "bind",
			dist:     OpenSUSE,
			wantErr:  "json unmarshal error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := NewVulnSrc(tt.dist)
			vulnsrctest.TestGet(t, vs, vulnsrctest.TestGetArgs{
				Fixtures:   tt.fixtures,
				WantValues: tt.want,
				GetParams: db.GetParams{
					Release: tt.version,
					PkgName: tt.pkgName,
				},
				WantErr: tt.wantErr,
			})
		})
	}
}

func TestStripArchSuffix(t *testing.T) {
	tests := map[string]string{
		"helm-mirror-0.2.1-1.7.1.x86_64": "helm-mirror-0.2.1-1.7.1",
		"pkg-1.2.3.aarch64":              "pkg-1.2.3",
		"pkg-1.0.noarch":                 "pkg-1.0",
		"pkg-1.0.ia64":                   "pkg-1.0",
		"pkg-1.0.aarch64_ilp32":          "pkg-1.0",
		"pkg-1.0.i686":                   "pkg-1.0",
		"pkg-1.2.3":                      "pkg-1.2.3",
	}
	for in, want := range tests {
		assert.Equal(t, want, stripArchSuffix(in))
	}
}

func Test_splitPkgName(t *testing.T) {
	tests := []struct {
		pkgName        string
		wantPkgName    string
		wantPkgVersion string
	}{
		{
			pkgName:        "helm-mirror-0.2.1-1.7.1",
			wantPkgName:    "helm-mirror",
			wantPkgVersion: "0.2.1-1.7.1",
		},
		{
			pkgName:        "python3-setuptools-58.2.0-1.1",
			wantPkgName:    "python3-setuptools",
			wantPkgVersion: "58.2.0-1.1",
		},
		{
			pkgName:        "helm-mirror-0:0.2.1-1.7.1",
			wantPkgName:    "helm-mirror",
			wantPkgVersion: "0:0.2.1-1.7.1",
		},
		{
			pkgName:        "bash-5.1.8-150400.9.1",
			wantPkgName:    "bash",
			wantPkgVersion: "5.1.8-150400.9.1",
		},
		{
			pkgName:        "libcurl4_32bit-7.66.0-150200.4.39.1",
			wantPkgName:    "libcurl4_32bit",
			wantPkgVersion: "7.66.0-150200.4.39.1",
		},
		{
			pkgName:        "pkg-with-many-dashes-in-name-1.0.0-1",
			wantPkgName:    "pkg-with-many-dashes-in-name",
			wantPkgVersion: "1.0.0-1",
		},
		{
			pkgName:        "pkg-1.0",
			wantPkgName:    "",
			wantPkgVersion: "",
		},
		{
			pkgName:        "pkg",
			wantPkgName:    "",
			wantPkgVersion: "",
		},
		{
			pkgName:        "",
			wantPkgName:    "",
			wantPkgVersion: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.pkgName, func(t *testing.T) {
			gotPkgName, gotPkgVersion := splitPkgName(tt.pkgName)
			assert.Equal(t, tt.wantPkgName, gotPkgName)
			assert.Equal(t, tt.wantPkgVersion, gotPkgVersion)
		})
	}
}

func TestGetOSVersion(t *testing.T) {
	testCases := []struct {
		inputPlatformName    string
		expectedPlatformName string
	}{
		{
			inputPlatformName:    "SUSE Linux Enterprise Workstation Extension 12 SP4",
			expectedPlatformName: "SUSE Linux Enterprise 12.4",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Module for Basesystem 15 SP1",
			expectedPlatformName: "SUSE Linux Enterprise 15.1",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server for SAP Applications 12 SP3-LTSS",
			expectedPlatformName: "SUSE Linux Enterprise 12.3",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Module for Containers 12",
			expectedPlatformName: "SUSE Linux Enterprise 12",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise High Availability 12 SP1",
			expectedPlatformName: "SUSE Linux Enterprise 12.1",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server for SAP Applications 12 SP1-LTSS",
			expectedPlatformName: "SUSE Linux Enterprise 12.1",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Module for High Performance Computing 12",
			expectedPlatformName: "SUSE Linux Enterprise 12",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Module for Live Patching 15",
			expectedPlatformName: "SUSE Linux Enterprise 15",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Module for Development Tools 15 SP1",
			expectedPlatformName: "SUSE Linux Enterprise 15.1",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Live Patching 12 SP5",
			expectedPlatformName: "SUSE Linux Enterprise 12.5",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Desktop 11 SP3",
			expectedPlatformName: "SUSE Linux Enterprise 11.3",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Module for Public Cloud 15 SP1",
			expectedPlatformName: "SUSE Linux Enterprise 15.1",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server 11-SECURITY",
			expectedPlatformName: "SUSE Linux Enterprise 11",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server for SAP Applications 11 SP4-CLIENT-TOOLS",
			expectedPlatformName: "SUSE Linux Enterprise 11.4",
		},
		{
			inputPlatformName:    "SUSE Package Hub for SUSE Linux Enterprise 12",
			expectedPlatformName: "SUSE Linux Enterprise 12",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Module for Open Buildservice Development Tools 15",
			expectedPlatformName: "SUSE Linux Enterprise 15",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Desktop 11 SP4",
			expectedPlatformName: "SUSE Linux Enterprise 11.4",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Module for CAP 15 SP1",
			expectedPlatformName: "SUSE Linux Enterprise 15.1",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server 12 SP5",
			expectedPlatformName: "SUSE Linux Enterprise 12.5",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Workstation Extension 15",
			expectedPlatformName: "SUSE Linux Enterprise 15",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Module for additional PackageHub packages 15",
			expectedPlatformName: "SUSE Linux Enterprise 15",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise High Availability 15 SP1",
			expectedPlatformName: "SUSE Linux Enterprise 15.1",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server 12 SP2-LTSS",
			expectedPlatformName: "SUSE Linux Enterprise 12.2",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise High Availability 12",
			expectedPlatformName: "SUSE Linux Enterprise 12",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Real Time Extension 12 SP1",
			expectedPlatformName: "SUSE Linux Enterprise 12.1",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Module for Advanced Systems Management 12",
			expectedPlatformName: "SUSE Linux Enterprise 12",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server 11 SP2-LTSS",
			expectedPlatformName: "SUSE Linux Enterprise 11.2",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server 11-LTSS",
			expectedPlatformName: "SUSE Linux Enterprise 11",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server 11-TERADATA",
			expectedPlatformName: "SUSE Linux Enterprise 11",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Module for Web Scripting 12",
			expectedPlatformName: "SUSE Linux Enterprise 12",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server 12 SP1-LTSS",
			expectedPlatformName: "SUSE Linux Enterprise 12.1",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Live Patching 12 SP3",
			expectedPlatformName: "SUSE Linux Enterprise 12.3",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server 12 SP3-LTSS",
			expectedPlatformName: "SUSE Linux Enterprise 12.3",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server 11 SP4",
			expectedPlatformName: "SUSE Linux Enterprise 11.4",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server for SAP Applications 12 SP2-BCL",
			expectedPlatformName: "SUSE Linux Enterprise 12.2",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Module for Python2 packages 15 SP1",
			expectedPlatformName: "SUSE Linux Enterprise 15.1",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server for SAP Applications 11 SP1-TERADATA",
			expectedPlatformName: "SUSE Linux Enterprise 11.1",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server for SAP Applications 11 SP3-CLIENT-TOOLS",
			expectedPlatformName: "SUSE Linux Enterprise 11.3",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Module for Web Scripting 15",
			expectedPlatformName: "SUSE Linux Enterprise 15",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server 11 SP3-TERADATA",
			expectedPlatformName: "SUSE Linux Enterprise 11.3",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Desktop 12 SP5",
			expectedPlatformName: "SUSE Linux Enterprise 12.5",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server 12 SP2-BCL",
			expectedPlatformName: "SUSE Linux Enterprise 12.2",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Workstation Extension 15 SP1",
			expectedPlatformName: "SUSE Linux Enterprise 15.1",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Software Development Kit 12 SP5",
			expectedPlatformName: "SUSE Linux Enterprise 12.5",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server 12",
			expectedPlatformName: "SUSE Linux Enterprise 12",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server 11 SP3-LTSS",
			expectedPlatformName: "SUSE Linux Enterprise 11.3",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise High Availability 12 SP5",
			expectedPlatformName: "SUSE Linux Enterprise 12.5",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Build System Kit 12",
			expectedPlatformName: "SUSE Linux Enterprise 12",
		},
		{
			inputPlatformName:    "SUSE Cloud Compute Node for SUSE Linux Enterprise 12 5",
			expectedPlatformName: "SUSE Linux Enterprise 12.5",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server 11-PUBCLOUD",
			expectedPlatformName: "SUSE Linux Enterprise 11",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise High Performance Computing 15-ESPOS",
			expectedPlatformName: "SUSE Linux Enterprise 15",
		},
		{
			inputPlatformName:    "openSUSE Leap 42.3",
			expectedPlatformName: "openSUSE Leap 42.3",
		},
		{
			inputPlatformName:    "openSUSE Leap 42.3 NonFree",
			expectedPlatformName: "openSUSE Leap 42.3",
		},
		{
			inputPlatformName:    "openSUSE Leap 15.1",
			expectedPlatformName: "openSUSE Leap 15.1",
		},
		{
			inputPlatformName:    "openSUSE Leap 15.1 NonFree",
			expectedPlatformName: "openSUSE Leap 15.1",
		},
		{
			inputPlatformName:    "openSUSE Leap Micro 15.1 NonFree",
			expectedPlatformName: "openSUSE Leap Micro 15.1",
		},
		{
			inputPlatformName:    "openSUSE Leap Micro 15.1",
			expectedPlatformName: "openSUSE Leap Micro 15.1",
		},
		{
			inputPlatformName:    "openSUSE Tumbleweed",
			expectedPlatformName: "openSUSE Tumbleweed",
		},
		// Below tests exclude platformNames
		{
			inputPlatformName:    "openSUSE Leap NonFree 15.1",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Module for SUSE Manager Server 4.0",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "HPE Helion Openstack 8",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "Openstack Cloud Magnum Orchestration 7",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "SUSE CaaS Platform ALL",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "SUSE Enterprise Storage 2.1",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "SUSE Enterprise Storage 6",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "SUSE Lifecycle Management Server 1.3",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "SUSE OpenStack Cloud 6-LTSS",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "SUSE OpenStack Cloud 9",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "SUSE OpenStack Cloud Crowbar 9",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "SUSE Studio Onsite 1.3",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "SUSE Studio Onsite Runner 1.3",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "SUSE WebYast 1.3",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "Subscription Management Tool 11 SP3",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "openSUSE 13.2",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "openSUSE 13.2 NonFree",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "openSUSE Evergreen 11.4",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Storage 7",
			expectedPlatformName: "",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Micro 5.1",
			expectedPlatformName: "SUSE Linux Enterprise Micro 5.1",
		},
		{
			inputPlatformName:    "SUSE Linux Micro 5.3",
			expectedPlatformName: "SUSE Linux Enterprise Micro 5.3",
		},
		{
			inputPlatformName:    "SUSE Linux Enterprise Server 16.0",
			expectedPlatformName: "SUSE Linux Enterprise 16.0",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.inputPlatformName, func(t *testing.T) {
			vs := NewVulnSrc(OpenSUSE)
			actual := vs.getOSVersion(tc.inputPlatformName)
			assert.Equal(t, tc.expectedPlatformName, actual, "input data: %s", tc.inputPlatformName)
		})
	}
}
