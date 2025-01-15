package redhatcsaf

import (
	"testing"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/types"
)

func TestAggregator_AggregateEntries(t *testing.T) {
	tests := []struct {
		name    string
		input   RawEntries
		want    Entries
		wantErr string
	}{
		{
			name: "CVE aggregation - different CVEs with same FixedVersion/Status/Arch/CPE",
			input: RawEntries{
				{
					FixedVersion: "1.0.0",
					Arch:         "x86_64",
					Alias:        "CVE-2024-1001",
					Severity:     types.SeverityHigh,
					CPE:          csaf.CPE("cpe:/o:redhat:enterprise_linux:9::baseos"),
				},
				{
					FixedVersion: "1.0.0",
					Arch:         "x86_64",
					Alias:        "CVE-2024-1002",
					Severity:     types.SeverityMedium,
					CPE:          csaf.CPE("cpe:/o:redhat:enterprise_linux:9::baseos"),
				},
			},
			want: Entries{
				{
					FixedVersion: "1.0.0",
					Arches:       []string{"x86_64"},
					AffectedCPEList: []string{
						"cpe:/o:redhat:enterprise_linux:9::baseos",
					},
					CVEs: []CVEEntry{
						{
							ID:       "CVE-2024-1001",
							Severity: types.SeverityHigh,
						},
						{
							ID:       "CVE-2024-1002",
							Severity: types.SeverityMedium,
						},
					},
				},
			},
		},
		{
			name: "CVE aggregation - unpatched vulnerability",
			input: RawEntries{
				{
					FixedVersion: "1.0.0",
					Status:       types.StatusAffected,
					Arch:         "x86_64",
					Alias:        "", // empty
					Severity:     types.SeverityHigh,
					CPE:          csaf.CPE("cpe:/o:redhat:enterprise_linux:9::baseos"),
				},
			},
			want: Entries{
				{
					FixedVersion: "1.0.0",
					Status:       types.StatusAffected,
					Arches:       []string{"x86_64"},
					AffectedCPEList: []string{
						"cpe:/o:redhat:enterprise_linux:9::baseos",
					},
					CVEs: []CVEEntry{
						{
							Severity: types.SeverityHigh,
						},
					},
				},
			},
		},
		{
			name: "Architecture aggregation - different Arch with same FixedVersion/Status/CVEs/CPE",
			input: RawEntries{
				{
					FixedVersion: "1.0.0",
					Status:       types.StatusFixed,
					Arch:         "x86_64",
					Alias:        "CVE-2024-1001",
					Severity:     types.SeverityHigh,
					CPE:          csaf.CPE("cpe:/o:redhat:enterprise_linux:9::baseos"),
				},
				{
					FixedVersion: "1.0.0",
					Status:       types.StatusFixed,
					Arch:         "aarch64",
					Alias:        "CVE-2024-1001",
					Severity:     types.SeverityHigh,
					CPE:          csaf.CPE("cpe:/o:redhat:enterprise_linux:9::baseos"),
				},
			},
			want: Entries{
				{
					FixedVersion: "1.0.0",
					Status:       types.StatusFixed,
					Arches:       []string{"aarch64", "x86_64"},
					AffectedCPEList: []string{
						"cpe:/o:redhat:enterprise_linux:9::baseos",
					},
					CVEs: []CVEEntry{
						{
							ID:       "CVE-2024-1001",
							Severity: types.SeverityHigh,
						},
					},
				},
			},
		},
		{
			name: "CPE aggregation - different CPE with same FixedVersion/Status/CVEs/Arches",
			input: RawEntries{
				{
					FixedVersion: "1.0.0",
					Status:       types.StatusFixed,
					Arch:         "x86_64",
					Alias:        "CVE-2024-1001",
					Severity:     types.SeverityHigh,
					CPE:          csaf.CPE("cpe:/o:redhat:enterprise_linux:8::baseos"),
				},
				{
					FixedVersion: "1.0.0",
					Status:       types.StatusFixed,
					Arch:         "x86_64",
					Alias:        "CVE-2024-1001",
					Severity:     types.SeverityHigh,
					CPE:          csaf.CPE("cpe:/o:redhat:enterprise_linux:9::baseos"),
				},
			},
			want: Entries{
				{
					FixedVersion: "1.0.0",
					Status:       types.StatusFixed,
					Arches:       []string{"x86_64"},
					AffectedCPEList: []string{
						"cpe:/o:redhat:enterprise_linux:8::baseos",
						"cpe:/o:redhat:enterprise_linux:9::baseos",
					},
					CVEs: []CVEEntry{
						{
							ID:       "CVE-2024-1001",
							Severity: types.SeverityHigh,
						},
					},
				},
			},
		},
		{
			name: "Error - duplicated CVEs",
			input: RawEntries{
				{
					FixedVersion: "1.0.0",
					Status:       types.StatusFixed,
					Arch:         "x86_64",
					Alias:        "CVE-2024-1001",
					Severity:     types.SeverityHigh,
					CPE:          csaf.CPE("cpe:/o:redhat:enterprise_linux:9::baseos"),
				},
				{
					FixedVersion: "1.0.0",
					Status:       types.StatusFixed,
					Arch:         "x86_64",
					Alias:        "CVE-2024-1001", // duplicated
					Severity:     types.SeverityMedium,
					CPE:          csaf.CPE("cpe:/o:redhat:enterprise_linux:9::baseos"),
				},
			},
			wantErr: "duplicated CVEs found",
		},
		{
			name: "Full aggregation - CVEs, Arches, and CPEs",
			input: RawEntries{
				{
					FixedVersion: "1.0.0",
					Arch:         "x86_64",
					Alias:        "CVE-2024-1001",
					Severity:     types.SeverityHigh,
					CPE:          csaf.CPE("cpe:/o:redhat:enterprise_linux:8::baseos"),
				},
				{
					FixedVersion: "1.0.0",
					Arch:         "x86_64",
					Alias:        "CVE-2024-1002",
					Severity:     types.SeverityMedium,
					CPE:          csaf.CPE("cpe:/o:redhat:enterprise_linux:8::baseos"),
				},
				{
					FixedVersion: "1.0.0",
					Arch:         "aarch64",
					Alias:        "CVE-2024-1001",
					Severity:     types.SeverityHigh,
					CPE:          csaf.CPE("cpe:/o:redhat:enterprise_linux:8::baseos"),
				},
				{
					FixedVersion: "1.0.0",
					Arch:         "aarch64",
					Alias:        "CVE-2024-1002",
					Severity:     types.SeverityMedium,
					CPE:          csaf.CPE("cpe:/o:redhat:enterprise_linux:8::baseos"),
				},
				{
					FixedVersion: "1.0.0",
					Arch:         "x86_64",
					Alias:        "CVE-2024-1001",
					Severity:     types.SeverityHigh,
					CPE:          csaf.CPE("cpe:/o:redhat:enterprise_linux:9::baseos"),
				},
				{
					FixedVersion: "1.0.0",
					Arch:         "x86_64",
					Alias:        "CVE-2024-1002",
					Severity:     types.SeverityMedium,
					CPE:          csaf.CPE("cpe:/o:redhat:enterprise_linux:9::baseos"),
				},
				{
					FixedVersion: "1.0.0",
					Arch:         "aarch64",
					Alias:        "CVE-2024-1001",
					Severity:     types.SeverityHigh,
					CPE:          csaf.CPE("cpe:/o:redhat:enterprise_linux:9::baseos"),
				},
				{
					FixedVersion: "1.0.0",
					Arch:         "aarch64",
					Alias:        "CVE-2024-1002",
					Severity:     types.SeverityMedium,
					CPE:          csaf.CPE("cpe:/o:redhat:enterprise_linux:9::baseos"),
				},
				{
					FixedVersion: "1.0.0",
					Arch:         "x86_64",
					Alias:        "CVE-2024-1001",
					Severity:     types.SeverityHigh,
					CPE:          csaf.CPE("cpe:/o:redhat:enterprise_linux:7::baseos"),
				},
			},
			want: Entries{
				{
					FixedVersion: "1.0.0",
					Arches:       []string{"x86_64"},
					AffectedCPEList: []string{
						"cpe:/o:redhat:enterprise_linux:7::baseos",
					},
					CVEs: []CVEEntry{
						{
							ID:       "CVE-2024-1001",
							Severity: types.SeverityHigh,
						},
					},
				},
				{
					FixedVersion: "1.0.0",
					Arches:       []string{"aarch64", "x86_64"},
					AffectedCPEList: []string{
						"cpe:/o:redhat:enterprise_linux:8::baseos",
						"cpe:/o:redhat:enterprise_linux:9::baseos",
					},
					CVEs: []CVEEntry{
						{
							ID:       "CVE-2024-1001",
							Severity: types.SeverityHigh,
						},
						{
							ID:       "CVE-2024-1002",
							Severity: types.SeverityMedium,
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agg := &Aggregator{}
			got, err := agg.AggregateEntries(tt.input)

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
