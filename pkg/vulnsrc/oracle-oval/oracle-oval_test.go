package oracleoval

import (
	fixtures "github.com/aquasecurity/bolt-fixtures"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	utils.Quiet = true
	os.Exit(m.Run())
}

func TestVulnSrc_Update(t *testing.T) {
	type want struct {
		key   []string
		value interface{}
	}
	tests := []struct {
		name       string
		dir        string
		wantValues []want
		wantErr    string
	}{
		{
			name: "happy path",
			dir:  filepath.Join("testdata", "happy path"),
			wantValues: []want{
				{
					key: []string{"data-source", "Oracle Linux 5"},
					value: types.DataSource{
						ID:   vulnerability.OracleOVAL,
						Name: "Oracle Linux OVAL definitions",
						URL:  "https://linux.oracle.com/security/oval/",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2007-0493", "Oracle Linux 5", "bind-devel"},
					value: types.Advisory{
						FixedVersion: "30:9.3.3-8.el5",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2007-0494", "Oracle Linux 5", "bind-devel"},
					value: types.Advisory{
						FixedVersion: "30:9.3.3-8.el5",
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2007-0493", "oracle-oval"},
					value: types.VulnerabilityDetail{
						Title:       "ELSA-2007-0057:  Moderate: bind security update  (MODERATE)",
						Description: "[30:9.3.3-8]\n - added fix for #224445 - CVE-2007-0493 BIND might crash after\n   attempting to read free()-ed memory\n - added fix for #225229 - CVE-2007-0494 BIND dnssec denial of service\n - Resolves: rhbz#224445\n - Resolves: rhbz#225229",
						References: []string{
							"http://linux.oracle.com/cve/CVE-2007-0493.html",
							"http://linux.oracle.com/errata/ELSA-2007-0057.html",
						},
						Severity: types.SeverityMedium,
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2007-0494", "oracle-oval"},
					value: types.VulnerabilityDetail{
						Title:       "ELSA-2007-0057:  Moderate: bind security update  (MODERATE)",
						Description: "[30:9.3.3-8]\n - added fix for #224445 - CVE-2007-0493 BIND might crash after\n   attempting to read free()-ed memory\n - added fix for #225229 - CVE-2007-0494 BIND dnssec denial of service\n - Resolves: rhbz#224445\n - Resolves: rhbz#225229",
						References: []string{
							"http://linux.oracle.com/cve/CVE-2007-0494.html",
							"http://linux.oracle.com/errata/ELSA-2007-0057.html",
						},
						Severity: types.SeverityMedium,
					},
				},
				{
					key:   []string{"vulnerability-id", "CVE-2007-0493"},
					value: map[string]interface{}{},
				},
				{
					key:   []string{"vulnerability-id", "CVE-2007-0494"},
					value: map[string]interface{}{},
				},
			},
		},
		{
			name: "happy path duplicate reference",
			dir:  filepath.Join("testdata", "duplicate reference"),
			wantValues: []want{
				{
					key: []string{"data-source", "Oracle Linux 5"},
					value: types.DataSource{
						ID:   vulnerability.OracleOVAL,
						Name: "Oracle Linux OVAL definitions",
						URL:  "https://linux.oracle.com/security/oval/",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2007-0493", "Oracle Linux 5", "bind-devel"},
					value: types.Advisory{
						FixedVersion: "30:9.3.3-8.el5",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2007-0494", "Oracle Linux 5", "bind-devel"},
					value: types.Advisory{
						FixedVersion: "30:9.3.3-8.el5",
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2007-0493", "oracle-oval"},
					value: types.VulnerabilityDetail{
						Title:       "ELSA-2007-0057:  Moderate: bind security update  (MODERATE)",
						Description: "[30:9.3.3-8]\n - added fix for #224445 - CVE-2007-0493 BIND might crash after\n   attempting to read free()-ed memory\n - added fix for #225229 - CVE-2007-0494 BIND dnssec denial of service\n - Resolves: rhbz#224445\n - Resolves: rhbz#225229",
						References: []string{
							"http://linux.oracle.com/cve/CVE-2007-0493.html",
							"http://linux.oracle.com/errata/ELSA-2007-0057.html",
						},
						Severity: types.SeverityMedium,
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2007-0494", "oracle-oval"},
					value: types.VulnerabilityDetail{
						Title:       "ELSA-2007-0057:  Moderate: bind security update  (MODERATE)",
						Description: "[30:9.3.3-8]\n - added fix for #224445 - CVE-2007-0493 BIND might crash after\n   attempting to read free()-ed memory\n - added fix for #225229 - CVE-2007-0494 BIND dnssec denial of service\n - Resolves: rhbz#224445\n - Resolves: rhbz#225229",
						References: []string{
							"http://linux.oracle.com/cve/CVE-2007-0494.html",
							"http://linux.oracle.com/errata/ELSA-2007-0057.html",
						},
						Severity: types.SeverityMedium,
					},
				},
				{
					key:   []string{"vulnerability-id", "CVE-2007-0493"},
					value: map[string]interface{}{},
				},
				{
					key:   []string{"vulnerability-id", "CVE-2007-0494"},
					value: map[string]interface{}{},
				},
			},
		},
		{
			name: "happy path multi platform",
			dir:  filepath.Join("testdata", "multi platform"),
			wantValues: []want{
				{
					key: []string{"data-source", "Oracle Linux 6"},
					value: types.DataSource{
						ID:   vulnerability.OracleOVAL,
						Name: "Oracle Linux OVAL definitions",
						URL:  "https://linux.oracle.com/security/oval/",
					},
				},
				{
					key: []string{"data-source", "Oracle Linux 7"},
					value: types.DataSource{
						ID:   vulnerability.OracleOVAL,
						Name: "Oracle Linux OVAL definitions",
						URL:  "https://linux.oracle.com/security/oval/",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2018-1094", "Oracle Linux 6", "kernel-uek-doc"},
					value: types.Advisory{
						FixedVersion: "4.1.12-124.24.3.el6uek",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2018-19824", "Oracle Linux 6", "kernel-uek-doc"},
					value: types.Advisory{
						FixedVersion: "4.1.12-124.24.3.el6uek",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2018-1094", "Oracle Linux 6", "kernel-uek-firmware"},
					value: types.Advisory{
						FixedVersion: "4.1.12-124.24.3.el6uek",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2018-19824", "Oracle Linux 6", "kernel-uek-firmware"},
					value: types.Advisory{
						FixedVersion: "4.1.12-124.24.3.el6uek",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2018-1094", "Oracle Linux 7", "kernel-uek-doc"},
					value: types.Advisory{
						FixedVersion: "4.1.12-124.24.3.el7uek",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2018-19824", "Oracle Linux 7", "kernel-uek-doc"},
					value: types.Advisory{
						FixedVersion: "4.1.12-124.24.3.el7uek",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2018-1094", "Oracle Linux 7", "kernel-uek-firmware"},
					value: types.Advisory{
						FixedVersion: "4.1.12-124.24.3.el7uek",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2018-19824", "Oracle Linux 7", "kernel-uek-firmware"},
					value: types.Advisory{
						FixedVersion: "4.1.12-124.24.3.el7uek",
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2018-1094", "oracle-oval"},
					value: types.VulnerabilityDetail{
						Title:       "ELSA-2019-4510: Unbreakable Enterprise kernel security update (IMPORTANT)",
						Description: "[4.1.12-124.24.3]\n- ext4: update i_disksize when new eof exceeds it (Shan Hai)  [Orabug: 28940828] \n- ext4: update i_disksize if direct write past ondisk size (Eryu Guan)  [Orabug: 28940828] \n- ext4: protect i_disksize update by i_data_sem in direct write path (Eryu Guan)  [Orabug: 28940828] \n- ALSA: usb-audio: Fix UAF decrement if card has no live interfaces in card.c (Hui Peng)  [Orabug: 29042981]  {CVE-2018-19824}\n- ALSA: usb-audio: Replace probing flag with active refcount (Takashi Iwai)  [Orabug: 29042981]  {CVE-2018-19824}\n- ALSA: usb-audio: Avoid nested autoresume calls (Takashi Iwai)  [Orabug: 29042981]  {CVE-2018-19824}\n- ext4: validate that metadata blocks do not overlap superblock (Theodore Ts'o)  [Orabug: 29114440]  {CVE-2018-1094}\n- ext4: update inline int ext4_has_metadata_csum(struct super_block *sb) (John Donnelly)  [Orabug: 29114440]  {CVE-2018-1094}\n- ext4: always initialize the crc32c checksum driver (Theodore Ts'o)  [Orabug: 29114440]  {CVE-2018-1094} {CVE-2018-1094}\n- Revert 'bnxt_en: Reduce default rings on multi-port cards.' (Brian Maly)  [Orabug: 28687746] \n- mlx4_core: Disable P_Key Violation Traps (Hakon Bugge)  [Orabug: 27693633] \n- rds: RDS connection does not reconnect after CQ access violation error (Venkat Venkatsubra)  [Orabug: 28733324]\n\n[4.1.12-124.24.2]\n- KVM/SVM: Allow direct access to MSR_IA32_SPEC_CTRL (KarimAllah Ahmed)  [Orabug: 28069548] \n- KVM/VMX: Allow direct access to MSR_IA32_SPEC_CTRL - reloaded (Mihai Carabas)  [Orabug: 28069548] \n- KVM/x86: Add IBPB support (Ashok Raj)  [Orabug: 28069548] \n- KVM: x86: pass host_initiated to functions that read MSRs (Paolo Bonzini)  [Orabug: 28069548] \n- KVM: VMX: make MSR bitmaps per-VCPU (Paolo Bonzini)  [Orabug: 28069548] \n- KVM: VMX: introduce alloc_loaded_vmcs (Paolo Bonzini)  [Orabug: 28069548] \n- KVM: nVMX: Eliminate vmcs02 pool (Jim Mattson)  [Orabug: 28069548] \n- KVM: nVMX: fix msr bitmaps to prevent L2 from accessing L0 x2APIC (Radim Krcmar)  [Orabug: 28069548] \n- ocfs2: dont clear bh uptodate for block read (Junxiao Bi)  [Orabug: 28762940] \n- ocfs2: clear journal dirty flag after shutdown journal (Junxiao Bi)  [Orabug: 28924775] \n- ocfs2: fix panic due to unrecovered local alloc (Junxiao Bi)  [Orabug: 28924775] \n- net: rds: fix rds_ib_sysctl_max_recv_allocation error (Zhu Yanjun)  [Orabug: 28947481] \n- x86/speculation: Always disable IBRS in disable_ibrs_and_friends() (Alejandro Jimenez)  [Orabug: 29139710]",
						References: []string{
							"https://linux.oracle.com/cve/CVE-2018-1094.html",
							"https://linux.oracle.com/errata/ELSA-2019-4510.html",
						},
						Severity: types.SeverityHigh,
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2018-19824", "oracle-oval"},
					value: types.VulnerabilityDetail{
						Title:       "ELSA-2019-4510: Unbreakable Enterprise kernel security update (IMPORTANT)",
						Description: "[4.1.12-124.24.3]\n- ext4: update i_disksize when new eof exceeds it (Shan Hai)  [Orabug: 28940828] \n- ext4: update i_disksize if direct write past ondisk size (Eryu Guan)  [Orabug: 28940828] \n- ext4: protect i_disksize update by i_data_sem in direct write path (Eryu Guan)  [Orabug: 28940828] \n- ALSA: usb-audio: Fix UAF decrement if card has no live interfaces in card.c (Hui Peng)  [Orabug: 29042981]  {CVE-2018-19824}\n- ALSA: usb-audio: Replace probing flag with active refcount (Takashi Iwai)  [Orabug: 29042981]  {CVE-2018-19824}\n- ALSA: usb-audio: Avoid nested autoresume calls (Takashi Iwai)  [Orabug: 29042981]  {CVE-2018-19824}\n- ext4: validate that metadata blocks do not overlap superblock (Theodore Ts'o)  [Orabug: 29114440]  {CVE-2018-1094}\n- ext4: update inline int ext4_has_metadata_csum(struct super_block *sb) (John Donnelly)  [Orabug: 29114440]  {CVE-2018-1094}\n- ext4: always initialize the crc32c checksum driver (Theodore Ts'o)  [Orabug: 29114440]  {CVE-2018-1094} {CVE-2018-1094}\n- Revert 'bnxt_en: Reduce default rings on multi-port cards.' (Brian Maly)  [Orabug: 28687746] \n- mlx4_core: Disable P_Key Violation Traps (Hakon Bugge)  [Orabug: 27693633] \n- rds: RDS connection does not reconnect after CQ access violation error (Venkat Venkatsubra)  [Orabug: 28733324]\n\n[4.1.12-124.24.2]\n- KVM/SVM: Allow direct access to MSR_IA32_SPEC_CTRL (KarimAllah Ahmed)  [Orabug: 28069548] \n- KVM/VMX: Allow direct access to MSR_IA32_SPEC_CTRL - reloaded (Mihai Carabas)  [Orabug: 28069548] \n- KVM/x86: Add IBPB support (Ashok Raj)  [Orabug: 28069548] \n- KVM: x86: pass host_initiated to functions that read MSRs (Paolo Bonzini)  [Orabug: 28069548] \n- KVM: VMX: make MSR bitmaps per-VCPU (Paolo Bonzini)  [Orabug: 28069548] \n- KVM: VMX: introduce alloc_loaded_vmcs (Paolo Bonzini)  [Orabug: 28069548] \n- KVM: nVMX: Eliminate vmcs02 pool (Jim Mattson)  [Orabug: 28069548] \n- KVM: nVMX: fix msr bitmaps to prevent L2 from accessing L0 x2APIC (Radim Krcmar)  [Orabug: 28069548] \n- ocfs2: dont clear bh uptodate for block read (Junxiao Bi)  [Orabug: 28762940] \n- ocfs2: clear journal dirty flag after shutdown journal (Junxiao Bi)  [Orabug: 28924775] \n- ocfs2: fix panic due to unrecovered local alloc (Junxiao Bi)  [Orabug: 28924775] \n- net: rds: fix rds_ib_sysctl_max_recv_allocation error (Zhu Yanjun)  [Orabug: 28947481] \n- x86/speculation: Always disable IBRS in disable_ibrs_and_friends() (Alejandro Jimenez)  [Orabug: 29139710]",
						References: []string{
							"https://linux.oracle.com/cve/CVE-2018-19824.html",
							"https://linux.oracle.com/errata/ELSA-2019-4510.html",
						},
						Severity: types.SeverityHigh,
					},
				},
				{
					key:   []string{"vulnerability-id", "CVE-2018-1094"},
					value: map[string]interface{}{},
				},
				{
					key:   []string{"vulnerability-id", "CVE-2018-19824"},
					value: map[string]interface{}{},
				},
			},
		},
		{
			name: "happy path multi package",
			dir:  filepath.Join("testdata", "multi package"),
			wantValues: []want{
				{
					key: []string{"data-source", "Oracle Linux 5"},
					value: types.DataSource{
						ID:   vulnerability.OracleOVAL,
						Name: "Oracle Linux OVAL definitions",
						URL:  "https://linux.oracle.com/security/oval/",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2007-0493", "Oracle Linux 5", "bind-devel"},
					value: types.Advisory{
						FixedVersion: "30:9.3.3-8.el5",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2007-0494", "Oracle Linux 5", "bind-devel"},
					value: types.Advisory{
						FixedVersion: "30:9.3.3-8.el5",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2007-0493", "Oracle Linux 5", "bind-sdb"},
					value: types.Advisory{
						FixedVersion: "30:9.3.3-8.el5",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2007-0494", "Oracle Linux 5", "bind-sdb"},
					value: types.Advisory{
						FixedVersion: "30:9.3.3-8.el5",
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2007-0493", "oracle-oval"},
					value: types.VulnerabilityDetail{
						Title:       "ELSA-2007-0057:  Moderate: bind security update  (MODERATE)",
						Description: "[30:9.3.3-8]\n - added fix for #224445 - CVE-2007-0493 BIND might crash after\n   attempting to read free()-ed memory\n - added fix for #225229 - CVE-2007-0494 BIND dnssec denial of service\n - Resolves: rhbz#224445\n - Resolves: rhbz#225229",
						References: []string{
							"http://linux.oracle.com/cve/CVE-2007-0493.html",
							"http://linux.oracle.com/errata/ELSA-2007-0057.html",
						},
						Severity: types.SeverityMedium,
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2007-0494", "oracle-oval"},
					value: types.VulnerabilityDetail{
						Title:       "ELSA-2007-0057:  Moderate: bind security update  (MODERATE)",
						Description: "[30:9.3.3-8]\n - added fix for #224445 - CVE-2007-0493 BIND might crash after\n   attempting to read free()-ed memory\n - added fix for #225229 - CVE-2007-0494 BIND dnssec denial of service\n - Resolves: rhbz#224445\n - Resolves: rhbz#225229",
						References: []string{
							"http://linux.oracle.com/cve/CVE-2007-0494.html",
							"http://linux.oracle.com/errata/ELSA-2007-0057.html",
						},
						Severity: types.SeverityMedium,
					},
				},
				{
					key:   []string{"vulnerability-id", "CVE-2007-0493"},
					value: map[string]interface{}{},
				},
				{
					key:   []string{"vulnerability-id", "CVE-2007-0494"},
					value: map[string]interface{}{},
				},
			},
		},
		{
			name: "happy path epoch 0",
			dir:  filepath.Join("testdata", "epoch 0"),
			wantValues: []want{
				{
					key: []string{"data-source", "Oracle Linux 5"},
					value: types.DataSource{
						ID:   vulnerability.OracleOVAL,
						Name: "Oracle Linux OVAL definitions",
						URL:  "https://linux.oracle.com/security/oval/",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2007-0493", "Oracle Linux 5", "bind-devel"},
					value: types.Advisory{
						FixedVersion: "9.3.3-8.el5",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2007-0494", "Oracle Linux 5", "bind-devel"},
					value: types.Advisory{
						FixedVersion: "9.3.3-8.el5",
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2007-0493", "oracle-oval"},
					value: types.VulnerabilityDetail{
						Title:       "ELSA-2007-0057:  Moderate: bind security update  (MODERATE)",
						Description: "[0:9.3.3-8]\n - added fix for #224445 - CVE-2007-0493 BIND might crash after\n   attempting to read free()-ed memory\n - added fix for #225229 - CVE-2007-0494 BIND dnssec denial of service\n - Resolves: rhbz#224445\n - Resolves: rhbz#225229",
						References: []string{
							"http://linux.oracle.com/cve/CVE-2007-0493.html",
							"http://linux.oracle.com/errata/ELSA-2007-0057.html",
						},
						Severity: types.SeverityMedium,
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2007-0494", "oracle-oval"},
					value: types.VulnerabilityDetail{
						Title:       "ELSA-2007-0057:  Moderate: bind security update  (MODERATE)",
						Description: "[0:9.3.3-8]\n - added fix for #224445 - CVE-2007-0493 BIND might crash after\n   attempting to read free()-ed memory\n - added fix for #225229 - CVE-2007-0494 BIND dnssec denial of service\n - Resolves: rhbz#224445\n - Resolves: rhbz#225229",
						References: []string{
							"http://linux.oracle.com/cve/CVE-2007-0494.html",
							"http://linux.oracle.com/errata/ELSA-2007-0057.html",
						},
						Severity: types.SeverityMedium,
					},
				},
				{
					key:   []string{"vulnerability-id", "CVE-2007-0493"},
					value: map[string]interface{}{},
				},
				{
					key:   []string{"vulnerability-id", "CVE-2007-0494"},
					value: map[string]interface{}{},
				},
			},
		},
		{
			name: "happy path nonCves",
			dir:  filepath.Join("testdata", "non CVEs"),
			wantValues: []want{
				{
					key: []string{"data-source", "Oracle Linux 5"},
					value: types.DataSource{
						ID:   vulnerability.OracleOVAL,
						Name: "Oracle Linux OVAL definitions",
						URL:  "https://linux.oracle.com/security/oval/",
					},
				},
				{
					key: []string{"advisory-detail", "ELSA-2007-0057", "Oracle Linux 5", "bind-devel"},
					value: types.Advisory{
						FixedVersion: "9.3.3-8.el5",
					},
				},
				{
					key: []string{"vulnerability-detail", "ELSA-2007-0057", "oracle-oval"},
					value: types.VulnerabilityDetail{
						Title:       "ELSA-2007-0057:  Moderate: bind security update  (MODERATE)",
						Description: "[0:9.3.3-8]\n - added fix for #224445 - CVE-2007-0493 BIND might crash after\n   attempting to read free()-ed memory\n - added fix for #225229 - CVE-2007-0494 BIND dnssec denial of service\n - Resolves: rhbz#224445\n - Resolves: rhbz#225229",
						References: []string{
							"http://linux.oracle.com/errata/ELSA-2007-0057.html",
						},
						Severity: types.SeverityMedium,
					},
				},
				{
					key:   []string{"vulnerability-id", "ELSA-2007-0057"},
					value: map[string]interface{}{},
				},
			},
		},
		{
			name: "empty package name",
			dir:  filepath.Join("testdata", "empty package name"),
			wantValues: []want{
				{
					key: []string{"vulnerability-detail", "CVE-0001-0001", "oracle-oval"},
					value: types.VulnerabilityDetail{
						Title:       "ELSA-0001-0001:  Moderate: empty security update  (N/A)",
						Description: "empty description",
						References: []string{
							"http://linux.oracle.com/cve/CVE-0001-0001.html",
							"http://linux.oracle.com/errata/ELSA-0001-0001.html",
						},
						Severity: types.SeverityUnknown,
					},
				},
				{
					key:   []string{"vulnerability-id", "CVE-0001-0001"},
					value: map[string]interface{}{},
				},
			},
		},
		{
			name: "unknown platform",
			dir:  filepath.Join("testdata", "empty package name"),
			wantValues: []want{
				{
					key: []string{"vulnerability-detail", "CVE-0001-0001", "oracle-oval"},
					value: types.VulnerabilityDetail{
						Title:       "ELSA-0001-0001:  Moderate: empty security update  (N/A)",
						Description: "empty description",
						References: []string{
							"http://linux.oracle.com/cve/CVE-0001-0001.html",
							"http://linux.oracle.com/errata/ELSA-0001-0001.html",
						},
						Severity: types.SeverityUnknown,
					},
				},
				{
					key:   []string{"vulnerability-id", "CVE-0001-0001"},
					value: map[string]interface{}{},
				},
			},
		},
		{
			name:    "sad path (dir doesn't exist)",
			dir:     filepath.Join("testdata", "badpathdoesnotexist"),
			wantErr: "no such file or directory",
		},
		{
			name:    "sad path (failed to decode)",
			dir:     filepath.Join("testdata", "failed to decode"),
			wantErr: "failed to decode Oracle Linux OVAL JSON",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()

			err := db.Init(tempDir)
			require.NoError(t, err)
			defer db.Close()

			vs := NewVulnSrc()
			err = vs.Update(tt.dir)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.NoError(t, db.Close()) // Need to close before dbtest.JSONEq is called
			for _, w := range tt.wantValues {
				dbtest.JSONEq(t, db.Path(tempDir), w.key, w.value, w.key)
			}
		})
	}
}

func TestVulnSrc_Get(t *testing.T) {
	tests := []struct {
		name     string
		fixtures []string
		version  string
		pkgName  string
		want     []types.Advisory
		wantErr  string
	}{
		{
			name:     "happy path",
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			version:  "8",
			pkgName:  "bind",
			want: []types.Advisory{
				{
					VulnerabilityID: "ELSA-2019-1145",
					FixedVersion:    "32:9.11.4-17.P2.el8_0",
				},
			},
		},
		{
			name:     "no advisories are returned",
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			version:  "8",
			pkgName:  "no-package",
			want:     nil,
		},
		{
			name:     "GetAdvisories returns an error",
			fixtures: []string{"testdata/fixtures/sad.yaml"},
			version:  "8",
			pkgName:  "bind",
			wantErr:  "failed to unmarshal advisory JSON",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := initDB(t, tt.fixtures)

			// Initialize DB
			require.NoError(t, db.Init(dir))
			defer db.Close()

			ac := NewVulnSrc()
			vuls, err := ac.Get(tt.version, tt.pkgName)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, vuls)
		})
	}
}

func initDB(t *testing.T, fixtureFiles []string) string {
	// Create a temp dir
	dir := t.TempDir()

	dbPath := db.Path(dir)
	dbDir := filepath.Dir(dbPath)
	err := os.MkdirAll(dbDir, 0700)
	require.NoError(t, err)

	// Load testdata into BoltDB
	loader, err := fixtures.New(dbPath, fixtureFiles)
	require.NoError(t, err)
	require.NoError(t, loader.Load())
	require.NoError(t, loader.Close())

	return dir
}
