package openeuler

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
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
		wantValues []vulnsrctest.WantValues
		wantErr    string
	}{
		{
			name: "happy path with openEuler",
			dir:  filepath.Join("testdata", "happy"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{
						"data-source",
						"openEuler-20.03-LTS",
					},
					Value: types.DataSource{
						ID:   vulnerability.OpenEuler,
						Name: "openEuler CVRF",
						URL:  "https://repo.openeuler.org/security/data/cvrf",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"openEuler-SA-2021-1061",
						"openEuler-20.03-LTS",
						"openjpeg",
					},
					Value: types.Advisory{
						FixedVersion: "1.5.1-25",
						Arches: []string{
							"aarch64",
							"noarch",
							"x86_64",
						},
					},
				},
				{
					Key: []string{
						"data-source",
						"openEuler-20.03-LTS-SP1",
					},
					Value: types.DataSource{
						ID:   vulnerability.OpenEuler,
						Name: "openEuler CVRF",
						URL:  "https://repo.openeuler.org/security/data/cvrf",
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"openEuler-SA-2021-1061",
						"openEuler-20.03-LTS-SP1",
						"openjpeg",
					},
					Value: types.Advisory{
						FixedVersion: "1.5.1-25",
						Arches: []string{
							"noarch",
							"x86_64",
						},
					},
				},
				{
					Key: []string{
						"vulnerability-detail",
						"openEuler-SA-2021-1061",
						"openeuler",
					},
					Value: types.VulnerabilityDetail{
						Title:       "An update for openjpeg is now available for openEuler-20.03-LTS and openEuler-20.03-LTS-SP1",
						Description: "\n\nSecurity Fix(es):\n\nHeap-based buffer overflow in the JPEG2000 image tile decoder in OpenJPEG before 1.5.2...",
						References: []string{
							"https://openeuler.org/en/security/safety-bulletin/detail.html?id=openEuler-SA-2021-1061",
							"https://openeuler.org/en/security/cve/detail.html?id=CVE-2014-0158",
							"https://nvd.nist.gov/vuln/detail/CVE-2014-0158",
						},
						Severity: types.SeverityHigh,
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"openEuler-SA-2021-1061",
					},
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
			wantErr: "failed to decode openEuler CVRF JSON",
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
		arch     string
		want     []types.Advisory
		wantErr  string
	}{
		{
			name:     "happy path",
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			version:  "22.03-LTS-SP2",
			pkgName:  "kernel",
			arch:     "aarch64",
			want: []types.Advisory{
				{
					VulnerabilityID: "openEuler-SA-2024-1349",
					FixedVersion:    "5.10.0-153.48.0.126",
					Arches: []string{
						"aarch64",
						"x86_64",
					},
				},
			},
		},
		{
			name:     "no arch found",
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			version:  "22.03-LTS-SP2",
			pkgName:  "kernel",
			arch:     "noarch",
			want:     nil,
		},
		{
			name:     "no advisories found",
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			version:  "23.09",
			pkgName:  "kernel",
			want:     nil,
		},
		{
			name:     "GetAdvisories returns an error",
			fixtures: []string{"testdata/fixtures/sad.yaml"},
			version:  "22.03-LTS-SP2",
			pkgName:  "kernel",
			wantErr:  "failed to unmarshal advisory JSON",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			vs := NewVulnSrc()
			got, err := vs.Get(tt.version, tt.pkgName, tt.arch)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSeverityFromThreat(t *testing.T) {
	testCases := map[string]types.Severity{
		"Low":      types.SeverityLow,
		"Medium":   types.SeverityMedium,
		"High":     types.SeverityHigh,
		"Critical": types.SeverityCritical,
		"":         types.SeverityUnknown,
		"None":     types.SeverityUnknown,
	}
	for k, v := range testCases {
		assert.Equal(t, v, severityFromThreat(k))
	}
}

func TestGetOSVersion(t *testing.T) {
	testCases := []struct {
		inputPlatformCPE  string
		expectedOsVersion string
	}{
		{
			inputPlatformCPE:  "cpe:/a:openEuler:openEuler:22.03-LTS-SP2",
			expectedOsVersion: "openEuler-22.03-LTS-SP2",
		},
		{
			inputPlatformCPE:  "cpe:/a:openEuler:openEuler:20.03-LTS",
			expectedOsVersion: "openEuler-20.03-LTS",
		},
		{
			inputPlatformCPE:  "cpe:/a:openEuler:openEuler:21.03",
			expectedOsVersion: "openEuler-21.03",
		},
		{
			inputPlatformCPE:  "cpe:/a:openEuler:openEuler-22.03-LTS",
			expectedOsVersion: "openEuler-22.03-LTS",
		},
		{
			inputPlatformCPE:  "cpe:/a:openEuler:openEuler",
			expectedOsVersion: "",
		},
		{
			inputPlatformCPE:  "cpe:/a:openEuler:openEuler:20.03-LTS-LTS-SP4",
			expectedOsVersion: "",
		},
		{
			inputPlatformCPE:  "cpe:/a:openEuler:23.09",
			expectedOsVersion: "",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.inputPlatformCPE, func(t *testing.T) {
			actual := getOSVersion(tc.inputPlatformCPE)
			assert.Equal(t, tc.expectedOsVersion, actual, fmt.Sprintf("input data: %s", tc.inputPlatformCPE))
		})
	}
}
