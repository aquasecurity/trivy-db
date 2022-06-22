package oracleoval

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
)

func TestMain(m *testing.M) {
	utils.Quiet = true
	os.Exit(m.Run())
}

func TestVulnSrc_Update(t *testing.T) {
	tests := []struct {
		name       string
		dir        string
		wantValues []vulnsrctest.WantValues
		wantErr    string
	}{
		{
			name: "happy path",
			dir:  filepath.Join("testdata", "happy"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"data-source", "Oracle Linux 5"},
					Value: types.DataSource{
						ID:   vulnerability.OracleOVAL,
						Name: "Oracle Linux OVAL definitions",
						URL:  "https://linux.oracle.com/security/oval/",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2007-0493", "Oracle Linux 5", "bind-devel"},
					Value: Advisory{
						FixedVersion: "30:9.3.3-8.el5",
						Entries: []Entry{
							{
								FixedVersion: "30:9.3.3-8.el5",
								VendorIDs:    []string{"ELSA-2007-0057"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2007-0494", "Oracle Linux 5", "bind-devel"},
					Value: Advisory{
						FixedVersion: "30:9.3.3-8.el5",
						Entries: []Entry{
							{
								FixedVersion: "30:9.3.3-8.el5",
								VendorIDs:    []string{"ELSA-2007-0057"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2007-0493", "Oracle Linux 5", "bind-sdb"},
					Value: Advisory{
						FixedVersion: "30:9.3.3-8.el5",
						Entries: []Entry{
							{
								FixedVersion: "30:9.3.3-8.el5",
								VendorIDs:    []string{"ELSA-2007-0057"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2007-0494", "Oracle Linux 5", "bind-sdb"},
					Value: Advisory{
						FixedVersion: "30:9.3.3-8.el5",
						Entries: []Entry{
							{
								FixedVersion: "30:9.3.3-8.el5",
								VendorIDs:    []string{"ELSA-2007-0057"},
							},
						},
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2007-0493", "oracle-oval"},
					Value: types.VulnerabilityDetail{
						References: []string{
							"http://linux.oracle.com/errata/ELSA-2007-0057.html",
							"http://linux.oracle.com/cve/CVE-2007-0493.html",
						},
						Severity: types.SeverityMedium,
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2007-0494", "oracle-oval"},
					Value: types.VulnerabilityDetail{
						References: []string{
							"http://linux.oracle.com/errata/ELSA-2007-0057.html",
							"http://linux.oracle.com/cve/CVE-2007-0494.html",
						},
						Severity: types.SeverityMedium,
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2007-0493"},
					Value: map[string]interface{}{},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2007-0494"},
					Value: map[string]interface{}{},
				},
			},
		},
		{
			name: "happy path multi platform",
			dir:  filepath.Join("testdata", "multi-platform"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"data-source", "Oracle Linux 6"},
					Value: types.DataSource{
						ID:   vulnerability.OracleOVAL,
						Name: "Oracle Linux OVAL definitions",
						URL:  "https://linux.oracle.com/security/oval/",
					},
				},
				{
					Key: []string{"data-source", "Oracle Linux 7"},
					Value: types.DataSource{
						ID:   vulnerability.OracleOVAL,
						Name: "Oracle Linux OVAL definitions",
						URL:  "https://linux.oracle.com/security/oval/",
					},
				},

				{
					Key: []string{"advisory-detail", "CVE-2018-1094", "Oracle Linux 6", "kernel-uek"},
					Value: Advisory{
						FixedVersion: "4.1.12-124.24.3.el6uek",
						Entries: []Entry{
							{
								FixedVersion: "4.1.12-124.24.3.el6uek",
								VendorIDs:    []string{"ELSA-2019-4510"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2018-19824", "Oracle Linux 6", "kernel-uek"},
					Value: Advisory{
						FixedVersion: "4.1.12-124.24.3.el6uek",
						Entries: []Entry{
							{
								FixedVersion: "4.1.12-124.24.3.el6uek",
								VendorIDs:    []string{"ELSA-2019-4510"},
							},
						},
					},
				},

				{
					Key: []string{"advisory-detail", "CVE-2018-1094", "Oracle Linux 6", "kernel-uek-debug"},
					Value: Advisory{
						FixedVersion: "4.1.12-124.24.3.el6uek",
						Entries: []Entry{
							{
								FixedVersion: "4.1.12-124.24.3.el6uek",
								VendorIDs:    []string{"ELSA-2019-4510"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2018-19824", "Oracle Linux 6", "kernel-uek-debug"},
					Value: Advisory{
						FixedVersion: "4.1.12-124.24.3.el6uek",
						Entries: []Entry{
							{
								FixedVersion: "4.1.12-124.24.3.el6uek",
								VendorIDs:    []string{"ELSA-2019-4510"},
							},
						},
					},
				},

				{
					Key: []string{"advisory-detail", "CVE-2018-1094", "Oracle Linux 6", "kernel-uek-debug-devel"},
					Value: Advisory{
						FixedVersion: "4.1.12-124.24.3.el6uek",
						Entries: []Entry{
							{
								FixedVersion: "4.1.12-124.24.3.el6uek",
								VendorIDs:    []string{"ELSA-2019-4510"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2018-19824", "Oracle Linux 6", "kernel-uek-debug-devel"},
					Value: Advisory{
						FixedVersion: "4.1.12-124.24.3.el6uek",
						Entries: []Entry{
							{
								FixedVersion: "4.1.12-124.24.3.el6uek",
								VendorIDs:    []string{"ELSA-2019-4510"},
							},
						},
					},
				},

				{
					Key: []string{"advisory-detail", "CVE-2018-1094", "Oracle Linux 6", "kernel-uek-devel"},
					Value: Advisory{
						FixedVersion: "4.1.12-124.24.3.el6uek",
						Entries: []Entry{
							{
								FixedVersion: "4.1.12-124.24.3.el6uek",
								VendorIDs:    []string{"ELSA-2019-4510"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2018-19824", "Oracle Linux 6", "kernel-uek-devel"},
					Value: Advisory{
						FixedVersion: "4.1.12-124.24.3.el6uek",
						Entries: []Entry{
							{
								FixedVersion: "4.1.12-124.24.3.el6uek",
								VendorIDs:    []string{"ELSA-2019-4510"},
							},
						},
					},
				},

				{
					Key: []string{"advisory-detail", "CVE-2018-1094", "Oracle Linux 6", "kernel-uek-doc"},
					Value: Advisory{
						FixedVersion: "4.1.12-124.24.3.el6uek",
						Entries: []Entry{
							{
								FixedVersion: "4.1.12-124.24.3.el6uek",
								VendorIDs:    []string{"ELSA-2019-4510"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2018-19824", "Oracle Linux 6", "kernel-uek-doc"},
					Value: Advisory{
						FixedVersion: "4.1.12-124.24.3.el6uek",
						Entries: []Entry{
							{
								FixedVersion: "4.1.12-124.24.3.el6uek",
								VendorIDs:    []string{"ELSA-2019-4510"},
							},
						},
					},
				},

				{
					Key: []string{"advisory-detail", "CVE-2018-1094", "Oracle Linux 6", "kernel-uek-firmware"},
					Value: Advisory{
						FixedVersion: "4.1.12-124.24.3.el6uek",
						Entries: []Entry{
							{
								FixedVersion: "4.1.12-124.24.3.el6uek",
								VendorIDs:    []string{"ELSA-2019-4510"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2018-19824", "Oracle Linux 6", "kernel-uek-firmware"},
					Value: Advisory{
						FixedVersion: "4.1.12-124.24.3.el6uek",
						Entries: []Entry{
							{
								FixedVersion: "4.1.12-124.24.3.el6uek",
								VendorIDs:    []string{"ELSA-2019-4510"},
							},
						},
					},
				},

				{
					Key: []string{"advisory-detail", "CVE-2018-1094", "Oracle Linux 7", "kernel-uek"},
					Value: Advisory{
						FixedVersion: "4.1.12-124.24.3.el7uek",
						Entries: []Entry{
							{
								FixedVersion: "4.1.12-124.24.3.el7uek",
								VendorIDs:    []string{"ELSA-2019-4510"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2018-19824", "Oracle Linux 7", "kernel-uek"},
					Value: Advisory{
						FixedVersion: "4.1.12-124.24.3.el7uek",
						Entries: []Entry{
							{
								FixedVersion: "4.1.12-124.24.3.el7uek",
								VendorIDs:    []string{"ELSA-2019-4510"},
							},
						},
					},
				},

				{
					Key: []string{"advisory-detail", "CVE-2018-1094", "Oracle Linux 7", "kernel-uek-debug"},
					Value: Advisory{
						FixedVersion: "4.1.12-124.24.3.el7uek",
						Entries: []Entry{
							{
								FixedVersion: "4.1.12-124.24.3.el7uek",
								VendorIDs:    []string{"ELSA-2019-4510"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2018-19824", "Oracle Linux 7", "kernel-uek-debug"},
					Value: Advisory{
						FixedVersion: "4.1.12-124.24.3.el7uek",
						Entries: []Entry{
							{
								FixedVersion: "4.1.12-124.24.3.el7uek",
								VendorIDs:    []string{"ELSA-2019-4510"},
							},
						},
					},
				},

				{
					Key: []string{"advisory-detail", "CVE-2018-1094", "Oracle Linux 7", "kernel-uek-debug-devel"},
					Value: Advisory{
						FixedVersion: "4.1.12-124.24.3.el7uek",
						Entries: []Entry{
							{
								FixedVersion: "4.1.12-124.24.3.el7uek",
								VendorIDs:    []string{"ELSA-2019-4510"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2018-19824", "Oracle Linux 7", "kernel-uek-debug-devel"},
					Value: Advisory{
						FixedVersion: "4.1.12-124.24.3.el7uek",
						Entries: []Entry{
							{
								FixedVersion: "4.1.12-124.24.3.el7uek",
								VendorIDs:    []string{"ELSA-2019-4510"},
							},
						},
					},
				},

				{
					Key: []string{"advisory-detail", "CVE-2018-1094", "Oracle Linux 7", "kernel-uek-devel"},
					Value: Advisory{
						FixedVersion: "4.1.12-124.24.3.el7uek",
						Entries: []Entry{
							{
								FixedVersion: "4.1.12-124.24.3.el7uek",
								VendorIDs:    []string{"ELSA-2019-4510"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2018-19824", "Oracle Linux 7", "kernel-uek-devel"},
					Value: Advisory{
						FixedVersion: "4.1.12-124.24.3.el7uek",
						Entries: []Entry{
							{
								FixedVersion: "4.1.12-124.24.3.el7uek",
								VendorIDs:    []string{"ELSA-2019-4510"},
							},
						},
					},
				},

				{
					Key: []string{"advisory-detail", "CVE-2018-1094", "Oracle Linux 7", "kernel-uek-doc"},
					Value: Advisory{
						FixedVersion: "4.1.12-124.24.3.el7uek",
						Entries: []Entry{
							{
								FixedVersion: "4.1.12-124.24.3.el7uek",
								VendorIDs:    []string{"ELSA-2019-4510"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2018-19824", "Oracle Linux 7", "kernel-uek-doc"},
					Value: Advisory{
						FixedVersion: "4.1.12-124.24.3.el7uek",
						Entries: []Entry{
							{
								FixedVersion: "4.1.12-124.24.3.el7uek",
								VendorIDs:    []string{"ELSA-2019-4510"},
							},
						},
					},
				},

				{
					Key: []string{"advisory-detail", "CVE-2018-1094", "Oracle Linux 7", "kernel-uek-firmware"},
					Value: Advisory{
						FixedVersion: "4.1.12-124.24.3.el7uek",
						Entries: []Entry{
							{
								FixedVersion: "4.1.12-124.24.3.el7uek",
								VendorIDs:    []string{"ELSA-2019-4510"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2018-19824", "Oracle Linux 7", "kernel-uek-firmware"},
					Value: Advisory{
						FixedVersion: "4.1.12-124.24.3.el7uek",
						Entries: []Entry{
							{
								FixedVersion: "4.1.12-124.24.3.el7uek",
								VendorIDs:    []string{"ELSA-2019-4510"},
							},
						},
					},
				},

				{
					Key: []string{"vulnerability-detail", "CVE-2018-1094", "oracle-oval"},
					Value: types.VulnerabilityDetail{
						References: []string{
							"https://linux.oracle.com/errata/ELSA-2019-4510.html",
							"https://linux.oracle.com/cve/CVE-2018-1094.html",
						},
						Severity: types.SeverityHigh,
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2018-19824", "oracle-oval"},
					Value: types.VulnerabilityDetail{
						References: []string{
							"https://linux.oracle.com/errata/ELSA-2019-4510.html",
							"https://linux.oracle.com/cve/CVE-2018-19824.html",
						},
						Severity: types.SeverityHigh,
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2018-1094"},
					Value: map[string]interface{}{},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2018-19824"},
					Value: map[string]interface{}{},
				},
			},
		},
		{
			name: "happy path multi flavors",
			dir:  filepath.Join("testdata", "multi-flavor"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"data-source", "Oracle Linux 8"},
					Value: types.DataSource{
						ID:   vulnerability.OracleOVAL,
						Name: "Oracle Linux OVAL definitions",
						URL:  "https://linux.oracle.com/security/oval/",
					},
				},

				{
					Key: []string{"advisory-detail", "CVE-2021-20232", "Oracle Linux 8", "gnutls"},
					Value: Advisory{
						FixedVersion: "3.6.16-4.el8",
						Entries: []Entry{
							{
								FixedVersion: "3.6.16-4.el8",
								VendorIDs:    []string{"ELSA-2021-4451"},
							},
							{
								FixedVersion: "10:3.6.16-4.0.1.el8_fips",
								VendorIDs:    []string{"ELSA-2022-9221"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-3580", "Oracle Linux 8", "gnutls"},
					Value: Advisory{
						FixedVersion: "3.6.16-4.el8",
						Entries: []Entry{
							{
								FixedVersion: "3.6.16-4.el8",
								VendorIDs:    []string{"ELSA-2021-4451"},
							},
							{
								FixedVersion: "10:3.6.16-4.0.1.el8_fips",
								VendorIDs:    []string{"ELSA-2022-9221"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-20231", "Oracle Linux 8", "gnutls"},
					Value: Advisory{
						FixedVersion: "3.6.16-4.el8",
						Entries: []Entry{
							{
								FixedVersion: "3.6.16-4.el8",
								VendorIDs:    []string{"ELSA-2021-4451"},
							},
							{
								FixedVersion: "10:3.6.16-4.0.1.el8_fips",
								VendorIDs:    []string{"ELSA-2022-9221"},
							},
						},
					},
				},

				{
					Key: []string{"advisory-detail", "CVE-2021-20232", "Oracle Linux 8", "nettle"},
					Value: Advisory{
						FixedVersion: "3.4.1-7.el8",
						Entries: []Entry{
							{
								FixedVersion: "3.4.1-7.el8",
								VendorIDs:    []string{"ELSA-2021-4451"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-3580", "Oracle Linux 8", "nettle"},
					Value: Advisory{
						FixedVersion: "3.4.1-7.el8",
						Entries: []Entry{
							{
								FixedVersion: "3.4.1-7.el8",
								VendorIDs:    []string{"ELSA-2021-4451"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-20231", "Oracle Linux 8", "nettle"},
					Value: Advisory{
						FixedVersion: "3.4.1-7.el8",
						Entries: []Entry{
							{
								FixedVersion: "3.4.1-7.el8",
								VendorIDs:    []string{"ELSA-2021-4451"},
							},
						},
					},
				},

				{
					Key: []string{"advisory-detail", "CVE-2021-20232", "Oracle Linux 8", "gnutls-c++"},
					Value: Advisory{
						FixedVersion: "3.6.16-4.el8",
						Entries: []Entry{
							{
								FixedVersion: "3.6.16-4.el8",
								VendorIDs:    []string{"ELSA-2021-4451"},
							},
							{
								FixedVersion: "10:3.6.16-4.0.1.el8_fips",
								VendorIDs:    []string{"ELSA-2022-9221"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-3580", "Oracle Linux 8", "gnutls-c++"},
					Value: Advisory{
						FixedVersion: "3.6.16-4.el8",
						Entries: []Entry{
							{
								FixedVersion: "3.6.16-4.el8",
								VendorIDs:    []string{"ELSA-2021-4451"},
							},
							{
								FixedVersion: "10:3.6.16-4.0.1.el8_fips",
								VendorIDs:    []string{"ELSA-2022-9221"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-20231", "Oracle Linux 8", "gnutls-c++"},
					Value: Advisory{
						FixedVersion: "3.6.16-4.el8",
						Entries: []Entry{
							{
								FixedVersion: "3.6.16-4.el8",
								VendorIDs:    []string{"ELSA-2021-4451"},
							},
							{
								FixedVersion: "10:3.6.16-4.0.1.el8_fips",
								VendorIDs:    []string{"ELSA-2022-9221"},
							},
						},
					},
				},

				{
					Key: []string{"advisory-detail", "CVE-2021-20232", "Oracle Linux 8", "gnutls-dane"},
					Value: Advisory{
						FixedVersion: "3.6.16-4.el8",
						Entries: []Entry{
							{
								FixedVersion: "3.6.16-4.el8",
								VendorIDs:    []string{"ELSA-2021-4451"},
							},
							{
								FixedVersion: "10:3.6.16-4.0.1.el8_fips",
								VendorIDs:    []string{"ELSA-2022-9221"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-3580", "Oracle Linux 8", "gnutls-dane"},
					Value: Advisory{
						FixedVersion: "3.6.16-4.el8",
						Entries: []Entry{
							{
								FixedVersion: "3.6.16-4.el8",
								VendorIDs:    []string{"ELSA-2021-4451"},
							},
							{
								FixedVersion: "10:3.6.16-4.0.1.el8_fips",
								VendorIDs:    []string{"ELSA-2022-9221"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-20231", "Oracle Linux 8", "gnutls-dane"},
					Value: Advisory{
						FixedVersion: "3.6.16-4.el8",
						Entries: []Entry{
							{
								FixedVersion: "3.6.16-4.el8",
								VendorIDs:    []string{"ELSA-2021-4451"},
							},
							{
								FixedVersion: "10:3.6.16-4.0.1.el8_fips",
								VendorIDs:    []string{"ELSA-2022-9221"},
							},
						},
					},
				},

				{
					Key: []string{"advisory-detail", "CVE-2021-20232", "Oracle Linux 8", "gnutls-devel"},
					Value: Advisory{
						FixedVersion: "3.6.16-4.el8",
						Entries: []Entry{
							{
								FixedVersion: "3.6.16-4.el8",
								VendorIDs:    []string{"ELSA-2021-4451"},
							},
							{
								FixedVersion: "10:3.6.16-4.0.1.el8_fips",
								VendorIDs:    []string{"ELSA-2022-9221"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-3580", "Oracle Linux 8", "gnutls-devel"},
					Value: Advisory{
						FixedVersion: "3.6.16-4.el8",
						Entries: []Entry{
							{
								FixedVersion: "3.6.16-4.el8",
								VendorIDs:    []string{"ELSA-2021-4451"},
							},
							{
								FixedVersion: "10:3.6.16-4.0.1.el8_fips",
								VendorIDs:    []string{"ELSA-2022-9221"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-20231", "Oracle Linux 8", "gnutls-devel"},
					Value: Advisory{
						FixedVersion: "3.6.16-4.el8",
						Entries: []Entry{
							{
								FixedVersion: "3.6.16-4.el8",
								VendorIDs:    []string{"ELSA-2021-4451"},
							},
							{
								FixedVersion: "10:3.6.16-4.0.1.el8_fips",
								VendorIDs:    []string{"ELSA-2022-9221"},
							},
						},
					},
				},

				{
					Key: []string{"advisory-detail", "CVE-2021-20232", "Oracle Linux 8", "gnutls-utils"},
					Value: Advisory{
						FixedVersion: "3.6.16-4.el8",
						Entries: []Entry{
							{
								FixedVersion: "3.6.16-4.el8",
								VendorIDs:    []string{"ELSA-2021-4451"},
							},
							{
								FixedVersion: "10:3.6.16-4.0.1.el8_fips",
								VendorIDs:    []string{"ELSA-2022-9221"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-3580", "Oracle Linux 8", "gnutls-utils"},
					Value: Advisory{
						FixedVersion: "3.6.16-4.el8",
						Entries: []Entry{
							{
								FixedVersion: "3.6.16-4.el8",
								VendorIDs:    []string{"ELSA-2021-4451"},
							},
							{
								FixedVersion: "10:3.6.16-4.0.1.el8_fips",
								VendorIDs:    []string{"ELSA-2022-9221"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-20231", "Oracle Linux 8", "gnutls-utils"},
					Value: Advisory{
						FixedVersion: "3.6.16-4.el8",
						Entries: []Entry{
							{
								FixedVersion: "3.6.16-4.el8",
								VendorIDs:    []string{"ELSA-2021-4451"},
							},
							{
								FixedVersion: "10:3.6.16-4.0.1.el8_fips",
								VendorIDs:    []string{"ELSA-2022-9221"},
							},
						},
					},
				},

				{
					Key: []string{"advisory-detail", "CVE-2021-20232", "Oracle Linux 8", "nettle-devel"},
					Value: Advisory{
						FixedVersion: "3.4.1-7.el8",
						Entries: []Entry{
							{
								FixedVersion: "3.4.1-7.el8",
								VendorIDs:    []string{"ELSA-2021-4451"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-3580", "Oracle Linux 8", "nettle-devel"},
					Value: Advisory{
						FixedVersion: "3.4.1-7.el8",
						Entries: []Entry{
							{
								FixedVersion: "3.4.1-7.el8",
								VendorIDs:    []string{"ELSA-2021-4451"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-20231", "Oracle Linux 8", "nettle-devel"},
					Value: Advisory{
						FixedVersion: "3.4.1-7.el8",
						Entries: []Entry{
							{
								FixedVersion: "3.4.1-7.el8",
								VendorIDs:    []string{"ELSA-2021-4451"},
							},
						},
					},
				},

				{
					Key: []string{"vulnerability-detail", "CVE-2021-20232", "oracle-oval"},
					Value: types.VulnerabilityDetail{
						References: []string{
							"https://linux.oracle.com/errata/ELSA-2021-4451.html",
							"https://linux.oracle.com/cve/CVE-2021-20232.html",
							"https://linux.oracle.com/errata/ELSA-2022-9221.html",
						},
						Severity: types.SeverityMedium,
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2021-3580", "oracle-oval"},
					Value: types.VulnerabilityDetail{
						References: []string{
							"https://linux.oracle.com/errata/ELSA-2021-4451.html",
							"https://linux.oracle.com/cve/CVE-2021-3580.html",
							"https://linux.oracle.com/errata/ELSA-2022-9221.html",
						},
						Severity: types.SeverityMedium,
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2021-20231", "oracle-oval"},
					Value: types.VulnerabilityDetail{
						References: []string{
							"https://linux.oracle.com/errata/ELSA-2021-4451.html",
							"https://linux.oracle.com/cve/CVE-2021-20231.html",
							"https://linux.oracle.com/errata/ELSA-2022-9221.html",
						},
						Severity: types.SeverityMedium,
					},
				},

				{
					Key:   []string{"vulnerability-id", "CVE-2021-20232"},
					Value: map[string]interface{}{},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2021-3580"},
					Value: map[string]interface{}{},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2021-20231"},
					Value: map[string]interface{}{},
				},
			},
		},
		{
			name: "happy path multiple ELSAs",
			dir:  filepath.Join("testdata", "multi-elsas"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"data-source", "Oracle Linux 8"},
					Value: types.DataSource{
						ID:   vulnerability.OracleOVAL,
						Name: "Oracle Linux OVAL definitions",
						URL:  "https://linux.oracle.com/security/oval/",
					},
				},

				{
					Key: []string{"advisory-detail", "CVE-2021-23133", "Oracle Linux 7", "kernel-uek"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.203.5.el7uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.203.5.el7uek",
								VendorIDs:    []string{"ELSA-2021-9306", "ELSA-2021-9362"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-33034", "Oracle Linux 7", "kernel-uek"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.203.5.el7uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.203.5.el7uek",
								VendorIDs:    []string{"ELSA-2021-9362"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2020-36310", "Oracle Linux 7", "kernel-uek"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.202.5.el7uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.202.5.el7uek",
								VendorIDs:    []string{"ELSA-2021-9306"},
							},
						},
					},
				},

				{
					Key: []string{"advisory-detail", "CVE-2021-23133", "Oracle Linux 7", "kernel-uek-debug"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.203.5.el7uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.203.5.el7uek",
								VendorIDs:    []string{"ELSA-2021-9306", "ELSA-2021-9362"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-33034", "Oracle Linux 7", "kernel-uek-debug"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.203.5.el7uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.203.5.el7uek",
								VendorIDs:    []string{"ELSA-2021-9362"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2020-36310", "Oracle Linux 7", "kernel-uek-debug"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.202.5.el7uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.202.5.el7uek",
								VendorIDs:    []string{"ELSA-2021-9306"},
							},
						},
					},
				},

				{
					Key: []string{"advisory-detail", "CVE-2021-23133", "Oracle Linux 7", "kernel-uek-debug-devel"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.203.5.el7uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.203.5.el7uek",
								VendorIDs:    []string{"ELSA-2021-9306", "ELSA-2021-9362"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-33034", "Oracle Linux 7", "kernel-uek-debug-devel"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.203.5.el7uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.203.5.el7uek",
								VendorIDs:    []string{"ELSA-2021-9362"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2020-36310", "Oracle Linux 7", "kernel-uek-debug-devel"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.202.5.el7uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.202.5.el7uek",
								VendorIDs:    []string{"ELSA-2021-9306"},
							},
						},
					},
				},

				{
					Key: []string{"advisory-detail", "CVE-2021-23133", "Oracle Linux 7", "kernel-uek-devel"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.203.5.el7uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.203.5.el7uek",
								VendorIDs:    []string{"ELSA-2021-9306", "ELSA-2021-9362"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-33034", "Oracle Linux 7", "kernel-uek-devel"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.203.5.el7uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.203.5.el7uek",
								VendorIDs:    []string{"ELSA-2021-9362"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2020-36310", "Oracle Linux 7", "kernel-uek-devel"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.202.5.el7uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.202.5.el7uek",
								VendorIDs:    []string{"ELSA-2021-9306"},
							},
						},
					},
				},

				{
					Key: []string{"advisory-detail", "CVE-2021-23133", "Oracle Linux 7", "kernel-uek-doc"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.203.5.el7uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.203.5.el7uek",
								VendorIDs:    []string{"ELSA-2021-9306", "ELSA-2021-9362"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-33034", "Oracle Linux 7", "kernel-uek-doc"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.203.5.el7uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.203.5.el7uek",
								VendorIDs:    []string{"ELSA-2021-9362"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2020-36310", "Oracle Linux 7", "kernel-uek-doc"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.202.5.el7uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.202.5.el7uek",
								VendorIDs:    []string{"ELSA-2021-9306"},
							},
						},
					},
				},

				{
					Key: []string{"advisory-detail", "CVE-2021-23133", "Oracle Linux 7", "kernel-uek-tools"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.203.5.el7uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.203.5.el7uek",
								VendorIDs:    []string{"ELSA-2021-9306", "ELSA-2021-9362"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-33034", "Oracle Linux 7", "kernel-uek-tools"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.203.5.el7uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.203.5.el7uek",
								VendorIDs:    []string{"ELSA-2021-9362"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2020-36310", "Oracle Linux 7", "kernel-uek-tools"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.202.5.el7uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.202.5.el7uek",
								VendorIDs:    []string{"ELSA-2021-9306"},
							},
						},
					},
				},

				{
					Key: []string{"advisory-detail", "CVE-2021-23133", "Oracle Linux 8", "kernel-uek"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.203.5.el8uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.203.5.el8uek",
								VendorIDs:    []string{"ELSA-2021-9306", "ELSA-2021-9362"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-33034", "Oracle Linux 8", "kernel-uek"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.203.5.el8uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.203.5.el8uek",
								VendorIDs:    []string{"ELSA-2021-9362"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2020-36310", "Oracle Linux 8", "kernel-uek"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.202.5.el8uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.202.5.el8uek",
								VendorIDs:    []string{"ELSA-2021-9306"},
							},
						},
					},
				},

				{
					Key: []string{"advisory-detail", "CVE-2021-23133", "Oracle Linux 8", "kernel-uek-debug"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.203.5.el8uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.203.5.el8uek",
								VendorIDs:    []string{"ELSA-2021-9306", "ELSA-2021-9362"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-33034", "Oracle Linux 8", "kernel-uek-debug"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.203.5.el8uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.203.5.el8uek",
								VendorIDs:    []string{"ELSA-2021-9362"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2020-36310", "Oracle Linux 8", "kernel-uek-debug"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.202.5.el8uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.202.5.el8uek",
								VendorIDs:    []string{"ELSA-2021-9306"},
							},
						},
					},
				},

				{
					Key: []string{"advisory-detail", "CVE-2021-23133", "Oracle Linux 8", "kernel-uek-debug-devel"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.203.5.el8uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.203.5.el8uek",
								VendorIDs:    []string{"ELSA-2021-9306", "ELSA-2021-9362"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-33034", "Oracle Linux 8", "kernel-uek-debug-devel"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.203.5.el8uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.203.5.el8uek",
								VendorIDs:    []string{"ELSA-2021-9362"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2020-36310", "Oracle Linux 8", "kernel-uek-debug-devel"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.202.5.el8uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.202.5.el8uek",
								VendorIDs:    []string{"ELSA-2021-9306"},
							},
						},
					},
				},

				{
					Key: []string{"advisory-detail", "CVE-2021-23133", "Oracle Linux 8", "kernel-uek-devel"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.203.5.el8uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.203.5.el8uek",
								VendorIDs:    []string{"ELSA-2021-9306", "ELSA-2021-9362"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-33034", "Oracle Linux 8", "kernel-uek-devel"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.203.5.el8uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.203.5.el8uek",
								VendorIDs:    []string{"ELSA-2021-9362"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2020-36310", "Oracle Linux 8", "kernel-uek-devel"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.202.5.el8uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.202.5.el8uek",
								VendorIDs:    []string{"ELSA-2021-9306"},
							},
						},
					},
				},

				{
					Key: []string{"advisory-detail", "CVE-2021-23133", "Oracle Linux 8", "kernel-uek-doc"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.203.5.el8uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.203.5.el8uek",
								VendorIDs:    []string{"ELSA-2021-9306", "ELSA-2021-9362"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-33034", "Oracle Linux 8", "kernel-uek-doc"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.203.5.el8uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.203.5.el8uek",
								VendorIDs:    []string{"ELSA-2021-9362"},
							},
						},
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2020-36310", "Oracle Linux 8", "kernel-uek-doc"},
					Value: Advisory{
						FixedVersion: "5.4.17-2102.202.5.el8uek",
						Entries: []Entry{
							{
								FixedVersion: "5.4.17-2102.202.5.el8uek",
								VendorIDs:    []string{"ELSA-2021-9306"},
							},
						},
					},
				},

				{
					Key: []string{"vulnerability-detail", "CVE-2021-33034", "oracle-oval"},
					Value: types.VulnerabilityDetail{
						References: []string{
							"https://linux.oracle.com/errata/ELSA-2021-9362.html",
							"https://linux.oracle.com/cve/CVE-2021-33034.html",
						},
						Severity: types.SeverityHigh,
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2020-36310", "oracle-oval"},
					Value: types.VulnerabilityDetail{
						References: []string{
							"https://linux.oracle.com/errata/ELSA-2021-9306.html",
							"https://linux.oracle.com/cve/CVE-2020-36310.html",
						},
						Severity: types.SeverityHigh,
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2021-23133", "oracle-oval"},
					Value: types.VulnerabilityDetail{
						References: []string{
							"https://linux.oracle.com/errata/ELSA-2021-9306.html",
							"https://linux.oracle.com/cve/CVE-2021-23133.html",
							"https://linux.oracle.com/errata/ELSA-2021-9362.html",
						},
						Severity: types.SeverityHigh,
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2021-23133"},
					Value: map[string]interface{}{},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2021-33034"},
					Value: map[string]interface{}{},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2020-36310"},
					Value: map[string]interface{}{},
				},
			},
		},
		{
			name: "happy path ELSA-ID",
			dir:  filepath.Join("testdata", "elsa-id"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"data-source", "Oracle Linux 5"},
					Value: types.DataSource{
						ID:   vulnerability.OracleOVAL,
						Name: "Oracle Linux OVAL definitions",
						URL:  "https://linux.oracle.com/security/oval/",
					},
				},
				{
					Key: []string{"advisory-detail", "ELSA-2007-0057", "Oracle Linux 5", "bind-devel"},
					Value: Advisory{
						FixedVersion: "9.3.3-8.el5",
						Entries: []Entry{
							{
								FixedVersion: "9.3.3-8.el5",
								VendorIDs:    []string{"ELSA-2007-0057"},
							},
						},
					},
				},
				{
					Key: []string{"vulnerability-detail", "ELSA-2007-0057", "oracle-oval"},
					Value: types.VulnerabilityDetail{
						References: []string{
							"http://linux.oracle.com/errata/ELSA-2007-0057.html",
						},
						Severity: types.SeverityMedium,
					},
				},
				{
					Key:   []string{"vulnerability-id", "ELSA-2007-0057"},
					Value: map[string]interface{}{},
				},
			},
		},
		{
			name: "unknown platform",
			dir:  filepath.Join("testdata", "unknown-platform"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"vulnerability-detail", "CVE-0001-0001", "oracle-oval"},
					Value: types.VulnerabilityDetail{
						References: []string{
							"http://linux.oracle.com/errata/ELSA-0001-0001.html",
							"http://linux.oracle.com/cve/CVE-0001-0001.html",
						},
						Severity: types.SeverityUnknown,
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-0001-0001"},
					Value: map[string]interface{}{},
				},
			},
		},
		{
			name: "multiple ksplice builds",
			dir:  filepath.Join("testdata", "ksplice"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"data-source", "Oracle Linux 8"},
					Value: types.DataSource{
						ID:   vulnerability.OracleOVAL,
						Name: "Oracle Linux OVAL definitions",
						URL:  "https://linux.oracle.com/security/oval/",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2016-10228", "Oracle Linux 8", "glibc"},
					Value: Advisory{
						Entries: []Entry{
							{
								FixedVersion: "2:2.28-151.0.1.ksplice2.el8",
								VendorIDs: []string{
									"ELSA-2021-9280",
									"ELSA-2021-9344",
								},
							},
						},
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2016-10228", "oracle-oval"},
					Value: types.VulnerabilityDetail{
						References: []string{
							"https://linux.oracle.com/errata/ELSA-2021-9280.html",
							"https://linux.oracle.com/cve/CVE-2016-10228.html",
							"https://linux.oracle.com/errata/ELSA-2021-9344.html",
						},
						Severity: types.SeverityHigh,
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2016-10228"},
					Value: map[string]interface{}{},
				},
			},
		},
		{
			name:    "sad path (dir doesn't exist)",
			dir:     filepath.Join("testdata", "badPath"),
			wantErr: "no such file or directory",
		},
		{
			name:    "sad path (failed to decode)",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "failed to decode Oracle Linux OVAL JSON",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := NewVulnSrc()
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
					VendorIDs:       []string{"ELSA-2019-1145"},
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
		{
			name:     "multi-flavors",
			fixtures: []string{"testdata/fixtures/multiple-elsas.yaml"},
			version:  "8",
			pkgName:  "gnutls",
			want: []types.Advisory{
				{
					VulnerabilityID: "CVE-2021-20231",
					VendorIDs:       []string{"ELSA-2021-4451"},
					FixedVersion:    "3.6.16-4.el8",
				},
				{
					VulnerabilityID: "CVE-2021-20232",
					VendorIDs:       []string{"ELSA-2021-4451"},
					FixedVersion:    "3.6.16-4.el8",
				},
				{
					VulnerabilityID: "CVE-2021-3580",
					VendorIDs:       []string{"ELSA-2021-4451"},
					FixedVersion:    "3.6.16-4.el8",
				},

				{
					VulnerabilityID: "CVE-2021-20231",
					VendorIDs:       []string{"ELSA-2022-9221"},
					FixedVersion:    "10:3.6.16-4.0.1.el8_fips",
				},
				{
					VulnerabilityID: "CVE-2021-20232",
					VendorIDs:       []string{"ELSA-2022-9221"},
					FixedVersion:    "10:3.6.16-4.0.1.el8_fips",
				},
				{
					VulnerabilityID: "CVE-2021-3580",
					VendorIDs:       []string{"ELSA-2022-9221"},
					FixedVersion:    "10:3.6.16-4.0.1.el8_fips",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := NewVulnSrc()
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
