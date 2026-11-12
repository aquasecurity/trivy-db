package nvd

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
)

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
					Key: []string{"vulnerability-detail", "CVE-2020-0001", "nvd"},
					Value: types.VulnerabilityDetail{
						Status:           "ANALYZED",
						Description:      "In getProcessRecordLocked of ActivityManagerService.java isolated apps are not handled correctly. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation. Product: Android Versions: Android-8.0, Android-8.1, Android-9, and Android-10 Android ID: A-140055304",
						CvssScore:        7.2,
						CvssVector:       "AV:L/AC:L/Au:N/C:C/I:C/A:C",
						CvssScoreV3:      7.8,
						CvssVectorV3:     "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
						Severity:         types.SeverityHigh,
						SeverityV3:       types.SeverityHigh,
						References:       []string{"https://source.android.com/security/bulletin/2020-01-01"},
						LastModifiedDate: utils.MustTimeParse("2021-07-21T11:39:23.747Z"),
						PublishedDate:    utils.MustTimeParse("2020-01-08T19:15:12.843Z"),
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2023-0001", "nvd"},
					Value: types.VulnerabilityDetail{
						Status:           "UNDERGOING ANALYSIS",
						Description:      "An information exposure vulnerability in the Palo Alto Networks Cortex XDR agent on Windows devices allows a local system administrator to disclose the admin password for the agent in cleartext, which bad actors can then use to execute privileged cytool commands that disable or uninstall the agent.",
						CvssScoreV3:      6.7,
						CvssVectorV3:     "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
						SeverityV3:       types.SeverityMedium,
						CweIDs:           []string{"CWE-319"},
						References:       []string{"https://security.paloaltonetworks.com/CVE-2023-0001"},
						LastModifiedDate: utils.MustTimeParse("2023-11-21T19:15:08.073Z"),
						PublishedDate:    utils.MustTimeParse("2023-02-08T18:15:11.523Z"),
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2024-0069", "nvd"},
					Value: types.VulnerabilityDetail{
						Status:           "REJECTED",
						Description:      "Rejected reason: This CVE ID was unused by the CNA.",
						LastModifiedDate: utils.MustTimeParse("2023-11-28T00:15:07.140Z"),
						PublishedDate:    utils.MustTimeParse("2023-11-28T00:15:07.140Z"),
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2024-5732", "nvd"},
					Value: types.VulnerabilityDetail{
						Status:      "ANALYZED",
						Description: "A vulnerability was found in Clash up to 0.20.1 on Windows. It has been declared as critical. This vulnerability affects unknown code of the component Proxy Port. The manipulation leads to improper authentication. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. It is recommended to change the configuration settings. VDB-267406 is the identifier assigned to this vulnerability.",
						// V2: no nvd@nist.gov metric => falls back to the CNA (vuldb) Secondary metric
						CvssScore:        7.5,
						CvssVector:       "AV:N/AC:L/Au:N/C:P/I:P/A:P",
						Severity:         types.SeverityHigh,
						CvssScoreV3:      9.8,
						CvssVectorV3:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
						CvssScoreV40:     6.9,
						CvssVectorV40:    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
						SeverityV3:       types.SeverityCritical,
						SeverityV40:      types.SeverityMedium,
						CweIDs:           []string{"CWE-287"},
						References:       []string{"https://github.com/GTA12138/vul/blob/main/clash%20for%20windows.md", "https://vuldb.com/?ctiid.267406", "https://vuldb.com/?id.267406", "https://vuldb.com/?submit.345469"},
						LastModifiedDate: utils.MustTimeParse("2024-06-11T17:57:13.767Z"),
						PublishedDate:    utils.MustTimeParse("2024-06-07T10:15:12.293Z"),
					},
				},
				{
					// No nvd@nist.gov metric at all: the only metric is a CISA-ADP
					// "Secondary" one, which the fallback must pick up.
					Key: []string{"vulnerability-detail", "CVE-2026-39834", "nvd"},
					Value: types.VulnerabilityDetail{
						Status:           "ANALYZED",
						Description:      "When writing data larger than 4GB in a single Write call on an SSH channel, an integer overflow in the internal payload size calculation caused the write loop to spin indefinitely, sending empty packets without making progress. The size comparison now uses int64 to prevent truncation.",
						CvssScoreV3:      9.1,
						CvssVectorV3:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H",
						SeverityV3:       types.SeverityCritical,
						CweIDs:           []string{"CWE-190"},
						References:       []string{"https://go.dev/cl/781663", "https://go.dev/issue/79567", "https://groups.google.com/g/golang-announce/c/a082jnz-LvI", "https://pkg.go.dev/vuln/GO-2026-5020"},
						LastModifiedDate: utils.MustTimeParse("2026-06-17T10:42:40.057Z"),
						PublishedDate:    utils.MustTimeParse("2026-05-22T04:16:24.237Z"),
					},
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
			wantErr: "json unmarshal error",
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

func Test_getCvssV3(t *testing.T) {
	nvdMetric := CvssMetricV3{
		Source: "nvd@nist.gov",
		Type:   "Primary",
		CvssData: CvssDataV30{
			VectorString: "CVSS:3.1/nvd",
			BaseScore:    7.0,
			BaseSeverity: "HIGH",
		},
	}
	cnaMetric := CvssMetricV3{
		Source: "security@golang.org",
		Type:   "Secondary",
		CvssData: CvssDataV30{
			VectorString: "CVSS:3.1/cna",
			BaseScore:    8.1,
			BaseSeverity: "HIGH",
		},
	}
	adpMetric := CvssMetricV3{
		Source: "134c704f-9b21-4f2e-91b3-4a467353bcc0",
		Type:   "Secondary",
		CvssData: CvssDataV30{
			VectorString: "CVSS:3.1/adp",
			BaseScore:    9.1,
			BaseSeverity: "CRITICAL",
		},
	}
	v30Metric := CvssMetricV3{
		Source: "134c704f-9b21-4f2e-91b3-4a467353bcc0",
		Type:   "Secondary",
		CvssData: CvssDataV30{
			VectorString: "CVSS:3.0/adp",
			BaseScore:    9.0,
			BaseSeverity: "CRITICAL",
		},
	}

	tests := []struct {
		name         string
		metricsV31   []CvssMetricV3
		metricsV30   []CvssMetricV3
		wantScore    float64
		wantVector   string
		wantSeverity types.Severity
	}{
		{
			name:         "NVD metric wins even when listed last",
			metricsV31:   []CvssMetricV3{adpMetric, cnaMetric, nvdMetric},
			wantScore:    7.0,
			wantVector:   "CVSS:3.1/nvd",
			wantSeverity: types.SeverityHigh,
		},
		{
			name:         "no NVD metric falls back to the first listed",
			metricsV31:   []CvssMetricV3{cnaMetric, adpMetric},
			wantScore:    8.1,
			wantVector:   "CVSS:3.1/cna",
			wantSeverity: types.SeverityHigh,
		},
		{
			name:         "Secondary ADP metric is used when it is the only one",
			metricsV31:   []CvssMetricV3{adpMetric},
			wantScore:    9.1,
			wantVector:   "CVSS:3.1/adp",
			wantSeverity: types.SeverityCritical,
		},
		{
			name:         "v3.1 fallback beats v3.0",
			metricsV31:   []CvssMetricV3{adpMetric},
			metricsV30:   []CvssMetricV3{v30Metric},
			wantScore:    9.1,
			wantVector:   "CVSS:3.1/adp",
			wantSeverity: types.SeverityCritical,
		},
		{
			name:         "no metrics",
			wantScore:    0,
			wantVector:   "",
			wantSeverity: types.SeverityUnknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotScore, gotVector, gotSeverity := getCvssV3(tt.metricsV31, tt.metricsV30)
			require.InDelta(t, tt.wantScore, gotScore, 0.001)
			require.Equal(t, tt.wantVector, gotVector)
			require.Equal(t, tt.wantSeverity, gotSeverity)
		})
	}
}
