package redhatcsaf

import (
	"maps"
	"path/filepath"
	"testing"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/types"
)

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name           string
		dir            string
		wantCPEs       []string
		wantAdvisories map[Bucket]RawEntries
		wantErr        string
	}{
		{
			name: "happy path",
			dir:  "testdata/happy",
			wantCPEs: []string{
				"cpe:/o:redhat:enterprise_linux:8::baseos",
				"cpe:/o:redhat:enterprise_linux:9::baseos",
			},
			wantAdvisories: map[Bucket]RawEntries{
				{
					Package: Package{
						Name: "affected-package",
					},
					VulnerabilityID: "CVE-2024-9999", // unpatched
				}: {
					{
						FixedVersion: "1.0.0",
						Arch:         "", // src package
						Severity:     types.SeverityHigh,
						CPE:          csaf.CPE("cpe:/o:redhat:enterprise_linux:9::baseos"),
					},
				},
				{
					Package: Package{
						Name: "pam",
					},
					VulnerabilityID: "RHSA-2024:9941",
				}: {
					{
						FixedVersion: "1.5.1-21.el9_5",
						Arch:         "x86_64",
						Alias:        "CVE-2024-10041",
						Status:       0, // omitted
						Severity:     types.SeverityMedium,
						CPE:          csaf.CPE("cpe:/o:redhat:enterprise_linux:9::baseos"),
					},
					{
						FixedVersion: "1.5.1-21.el9_5",
						Arch:         "aarch64",
						Alias:        "CVE-2024-10041",
						Status:       0, // omitted
						Severity:     types.SeverityMedium,
						CPE:          csaf.CPE("cpe:/o:redhat:enterprise_linux:9::baseos"),
					},
				},
				{
					Package: Package{
						Name: "test-namespace/test-package",
					},
					VulnerabilityID: "RHSA-2024:9999",
				}: {
					{
						FixedVersion: "1:1.0.0-1.el9",
						Arch:         "x86_64",
						Alias:        "CVE-2024-9999",
						Severity:     types.SeverityHigh,
						CPE:          csaf.CPE("cpe:/o:redhat:enterprise_linux:9::baseos"),
					},
				},
			},
		},
		{
			name:    "empty CVE ID",
			dir:     filepath.Join("testdata", "empty-cve"),
			wantErr: "does not match ^CVE-[0-9]{4}-[0-9]{4,}",
		},
		{
			name:    "no vulnerabilities",
			dir:     filepath.Join("testdata", "no-vulnerabilities"),
			wantErr: "invalid number of vulnerabilities",
		},
		{
			name:    "no CSAF VEX dir",
			dir:     filepath.Join("testdata", "no-csaf-vex"),
			wantErr: "no such file or directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewParser()
			err := parser.Parse(tt.dir)

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)

			// Verify CPE list
			cpeList := parser.CPEList()
			for _, wantCPE := range tt.wantCPEs {
				assert.Contains(t, cpeList, wantCPE)
			}

			// Collect advisories
			gotAdvisories := maps.Collect(parser.Advisories())

			// Verify advisories
			assert.Equal(t, tt.wantAdvisories, gotAdvisories)
		})
	}
}

func TestParser_DetectStatus(t *testing.T) {
	tests := []struct {
		name     string
		category csaf.RemediationCategory
		details  string
		want     types.Status
	}{
		{
			name:     "vendor fix",
			category: csaf.CSAFRemediationCategoryVendorFix,
			want:     types.StatusFixed,
		},
		{
			name:     "end of life",
			category: csaf.CSAFRemediationCategoryNoFixPlanned,
			details:  "Out of support scope",
			want:     types.StatusEndOfLife,
		},
		{
			name:     "will not fix",
			category: csaf.CSAFRemediationCategoryNoFixPlanned,
			details:  "Will not fix",
			want:     types.StatusWillNotFix,
		},
		{
			name:     "affected",
			category: csaf.CSAFRemediationCategoryNoneAvailable,
			details:  "Affected",
			want:     types.StatusAffected,
		},
		{
			name:     "fix deferred",
			category: csaf.CSAFRemediationCategoryNoneAvailable,
			details:  "Deferred",
			want:     types.StatusFixDeferred,
		},
		{
			name:     "unknown",
			category: "unknown",
			want:     types.StatusUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewParser()
			remediation := &csaf.Remediation{
				Category: &tt.category,
				Details:  &tt.details,
			}

			got := parser.detectStatus(remediation)
			assert.Equal(t, tt.want, got)
		})
	}
}
