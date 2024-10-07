package susecvrf

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

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
		wantErr    string
	}{
		{
			name: "happy path with openSUSE",
			dir:  filepath.Join("testdata", "happy", "openSUSE"),
			dist: OpenSUSE,
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"data-source", "openSUSE Leap 15.1"},
					Value: types.DataSource{
						ID:   vulnerability.SuseCVRF,
						Name: "SUSE CVRF",
						URL:  "https://ftp.suse.com/pub/projects/security/cvrf/",
					},
				},
				{
					Key: []string{"advisory-detail", "openSUSE-SU-2019:2598-1", "openSUSE Leap 15.1", "strongswan"},
					Value: types.Advisory{
						FixedVersion: "5.6.0-lp151.4.3.1",
					},
				},
				{
					Key: []string{"advisory-detail", "openSUSE-SU-2019:2598-1", "openSUSE Leap 15.1", "strongswan-sqlite"},
					Value: types.Advisory{
						FixedVersion: "5.6.0-lp151.4.3.1",
					},
				},
				{
					Key: []string{"vulnerability-detail", "openSUSE-SU-2019:2598-1", "suse-cvrf"},
					Value: types.VulnerabilityDetail{
						Title:       "Security update for strongswan",
						Description: "This update for strongswan fixes the following issues:\n\nSecurity issues fixed: \n\n- CVE-2018-5388: Fixed a buffer underflow which may allow to a remote attacker \n  with local user credentials to resource exhaustion and denial of service while \n  reading from the socket (bsc#1094462).\n- CVE-2018-10811: Fixed a denial of service during  the IKEv2 key derivation if \n  the openssl plugin is used in FIPS mode and HMAC-MD5 is negotiated as PRF \n  (bsc#1093536).\n- CVE-2018-16151,CVE-2018-16152: Fixed multiple flaws in the gmp plugin which \n  might lead to authorization bypass (bsc#1107874).\n- CVE-2018-17540: Fixed an improper input validation in gmp plugin (bsc#1109845).  \n\nThis update was imported from the SUSE:SLE-15:Update update project.",
						References: []string{
							"https://lists.opensuse.org/opensuse-security-announce/2019-12/msg00001.html",
							"https://www.suse.com/support/security/rating/",
						},
						Severity: types.SeverityHigh,
					},
				},
				{
					Key:   []string{"vulnerability-id", "openSUSE-SU-2019:2598-1"},
					Value: map[string]interface{}{},
				},
			},
		},
		{
			name: "happy path with openSUSE Tumbleweed",
			dir:  filepath.Join("testdata", "happy", "openSUSE Tumbleweed"),
			dist: OpenSUSETumbleweed,
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"data-source", "openSUSE Tumbleweed"},
					Value: types.DataSource{
						ID:   vulnerability.SuseCVRF,
						Name: "SUSE CVRF",
						URL:  "https://ftp.suse.com/pub/projects/security/cvrf/",
					},
				},
				{
					Key: []string{"advisory-detail", "openSUSE-SU-2024:10400-1", "openSUSE Tumbleweed", "python3-logilab-common"},
					Value: types.Advisory{
						FixedVersion: "1.2.2-1.2",
					},
				},
				{
					Key: []string{"advisory-detail", "openSUSE-SU-2024:10400-1", "openSUSE Tumbleweed", "python-logilab-common"},
					Value: types.Advisory{
						FixedVersion: "1.0.2-1.4",
					},
				},
				{
					Key: []string{"vulnerability-detail", "openSUSE-SU-2024:10400-1", "suse-cvrf"},
					Value: types.VulnerabilityDetail{
						Title:       "python-logilab-common-1.0.2-1.4 on GA media",
						Description: "These are all security issues fixed in the python-logilab-common-1.0.2-1.4 package on the GA media of openSUSE Tumbleweed.",
						References: []string{
							"https://www.suse.com/support/security/rating/",
							"https://www.suse.com/security/cve/CVE-2014-1838/",
							"https://www.suse.com/security/cve/CVE-2014-1839/",
						},
						Severity: types.SeverityMedium,
					},
				},
				{
					Key:   []string{"vulnerability-id", "openSUSE-SU-2024:10400-1"},
					Value: map[string]interface{}{},
				},
			},
		},
		{
			name: "happy path with SUSE Enterprise Linux",
			dir:  filepath.Join("testdata", "happy", "SUSE Enterprise Linux"),
			dist: SUSEEnterpriseLinux,
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"data-source", "SUSE Linux Enterprise 15.1"},
					Value: types.DataSource{
						ID:   vulnerability.SuseCVRF,
						Name: "SUSE CVRF",
						URL:  "https://ftp.suse.com/pub/projects/security/cvrf/",
					},
				},
				{
					Key: []string{"advisory-detail", "SUSE-SU-2019:0048-2", "SUSE Linux Enterprise 15.1", "helm-mirror"},
					Value: types.Advisory{
						FixedVersion: "0.2.1-1.7.1",
					},
				},
				{
					Key: []string{"vulnerability-detail", "SUSE-SU-2019:0048-2", "suse-cvrf"},
					Value: types.VulnerabilityDetail{
						Title:       "Security update for helm-mirror",
						Description: "This update for helm-mirror to version 0.2.1 fixes the following issues:\n\n\nSecurity issues fixed:\n\n- CVE-2018-16873: Fixed a remote command execution (bsc#1118897)\n- CVE-2018-16874: Fixed a directory traversal in &quot;go get&quot; via curly braces in import path (bsc#1118898)\n- CVE-2018-16875: Fixed a CPU denial of service (bsc#1118899)\n\nNon-security issue fixed:\n\n- Update to v0.2.1 (bsc#1120762)\n- Include helm-mirror into the containers module (bsc#1116182)\n",
						References: []string{
							"https://www.suse.com/support/update/announcement/2019/suse-su-20190048-2/",
							"http://lists.suse.com/pipermail/sle-security-updates/2019-July/005660.html",
							"https://www.suse.com/support/security/rating/",
						},
						Severity: types.SeverityHigh,
					},
				},
				{
					Key:   []string{"vulnerability-id", "SUSE-SU-2019:0048-2"},
					Value: map[string]interface{}{},
				},
			},
		},
		{
			name: "happy path with openSUSE CVRF including SUSE Linux Enterprise Linux",
			dir:  filepath.Join("testdata", "happy", "openSUSE CVRF including SUSE Linux Enterprise Linux"),
			dist: OpenSUSE,
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"data-source", "SUSE Linux Enterprise 15"},
					Value: types.DataSource{
						ID:   vulnerability.SuseCVRF,
						Name: "SUSE CVRF",
						URL:  "https://ftp.suse.com/pub/projects/security/cvrf/",
					},
				},
				{
					Key: []string{"advisory-detail", "openSUSE-SU-2019:0003-1", "SUSE Linux Enterprise 15", "GraphicsMagick"},
					Value: types.Advisory{
						FixedVersion: "1.3.29-bp150.2.12.1",
					},
				},
				{
					Key: []string{"advisory-detail", "openSUSE-SU-2019:0003-1", "SUSE Linux Enterprise 15", "GraphicsMagick-devel"},
					Value: types.Advisory{
						FixedVersion: "1.3.29-bp150.2.12.1",
					},
				},
				{
					Key: []string{"vulnerability-detail", "openSUSE-SU-2019:0003-1", "suse-cvrf"},
					Value: types.VulnerabilityDetail{
						Title:       "Security update for GraphicsMagick",
						Description: "This update for GraphicsMagick fixes the following issues:\n\nSecurity vulnerabilities fixed:\n\n- CVE-2018-20184: Fixed heap-based buffer overflow in the WriteTGAImage function of tga.c (bsc#1119822)\n- CVE-2018-20189: Fixed denial of service vulnerability in ReadDIBImage function of coders/dib.c (bsc#1119790)\n\nThis update was imported from the openSUSE:Leap:15.0:Update update project.",
						References: []string{
							"http://lists.opensuse.org/opensuse-security-announce/2019-01/msg00001.html",
							"https://www.suse.com/support/security/rating/",
						},
						Severity: types.SeverityMedium,
					},
				},
				{
					Key:   []string{"vulnerability-id", "openSUSE-SU-2019:0003-1"},
					Value: map[string]interface{}{},
				},
			},
		},
		{
			name: "happy path with SLE Micro CVRF including SUSE Linux Enterprise Micro",
			dir:  filepath.Join("testdata", "happy", "SUSE Linux Enterprise Micro"),
			dist: SUSEEnterpriseLinuxMicro,
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"data-source", "SUSE Linux Enterprise Micro 5.3"},
					Value: types.DataSource{
						ID:   vulnerability.SuseCVRF,
						Name: "SUSE CVRF",
						URL:  "https://ftp.suse.com/pub/projects/security/cvrf/",
					},
				},
				{
					Key: []string{"advisory-detail", "SUSE-SU-2024:2546-1", "SUSE Linux Enterprise Micro 5.3", "gnutls"},

					Value: types.Advisory{
						FixedVersion: "3.7.3-150400.8.1",
					},
				},
				{
					Key: []string{"advisory-detail", "SUSE-SU-2024:2546-1", "SUSE Linux Enterprise Micro 5.3", "libgnutls30"},
					Value: types.Advisory{
						FixedVersion: "3.7.3-150400.8.1",
					},
				},
				{
					Key: []string{"vulnerability-detail", "SUSE-SU-2024:2546-1", "suse-cvrf"},
					Value: types.VulnerabilityDetail{
						Title:       "Security update for gnutls",
						Description: "This update for gnutls fixes the following issues:\n\n- CVE-2024-28835: Fixed a certtool crash when verifying a certificate\n  chain (bsc#1221747).\n- CVE-2024-28834: Fixed a side-channel attack in the deterministic\n  ECDSA (bsc#1221746).\n\nOther fixes:\n\n- Fixed a memory leak when using the entropy collector (bsc#1221242).\n",
						References: []string{
							"https://www.suse.com/support/update/announcement/2024/suse-su-20242546-1/",
							"https://lists.suse.com/pipermail/sle-security-updates/2024-July/018994.html",
							"https://www.suse.com/support/security/rating/",
							"https://bugzilla.suse.com/1221242",
							"https://bugzilla.suse.com/1221746",
							"https://bugzilla.suse.com/1221747",
							"https://www.suse.com/security/cve/CVE-2024-28834/",
							"https://www.suse.com/security/cve/CVE-2024-28835/",
						},
						Severity: types.SeverityMedium,
					},
				},
				{
					Key:   []string{"vulnerability-id", "SUSE-SU-2024:2546-1"},
					Value: map[string]interface{}{},
				},
			},
		},
		{
			name:    "sad path (dir doesn't exist)",
			dir:     filepath.Join("testdata", "badPath"),
			dist:    OpenSUSE,
			wantErr: "no such file or directory",
		},
		{
			name:    "sad path (failed to decode)",
			dir:     filepath.Join("testdata", "sad"),
			dist:    OpenSUSE,
			wantErr: "failed to decode SUSE CVRF JSON",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := NewVulnSrc(tt.dist)
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
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
			wantErr:  "failed to unmarshal advisory JSON",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := NewVulnSrc(tt.dist)
			vulnsrctest.TestGet(t, vs, vulnsrctest.TestGetArgs{
				Fixtures:   tt.fixtures,
				WantValues: tt.want,
				Release:    tt.version,
				PkgName:    tt.pkgName,
				WantErr:    tt.wantErr,
			})
		})
	}
}

func TestSeverityFromThreat(t *testing.T) {
	testCases := map[string]types.Severity{
		"low":       types.SeverityLow,
		"moderate":  types.SeverityMedium,
		"important": types.SeverityHigh,
		"critical":  types.SeverityCritical,
		"":          types.SeverityUnknown,
		"invalid":   types.SeverityUnknown,
	}
	for k, v := range testCases {
		assert.Equal(t, v, severityFromThreat(k))
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
	}
	for _, tc := range testCases {
		t.Run(tc.inputPlatformName, func(t *testing.T) {
			actual := getOSVersion(tc.inputPlatformName)
			assert.Equal(t, tc.expectedPlatformName, actual, fmt.Sprintf("input data: %s", tc.inputPlatformName))
		})
	}
}
