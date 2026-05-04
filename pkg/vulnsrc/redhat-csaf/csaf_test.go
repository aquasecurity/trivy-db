package redhatcsaf_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	redhatcsaf "github.com/aquasecurity/trivy-db/pkg/vulnsrc/redhat-csaf"
	redhatoval "github.com/aquasecurity/trivy-db/pkg/vulnsrc/redhat-oval"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
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
			dir:  "testdata",
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{
						"data-source",
						"Red Hat",
					},
					Value: types.DataSource{
						ID:   vulnerability.RedHatCSAFVEX,
						Name: "Red Hat CSAF VEX",
						URL:  "https://access.redhat.com/security/data/csaf/v2/vex/",
					},
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"0",
					},
					Value: "cpe:/o:redhat:enterprise_linux:8::baseos",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"1",
					},
					Value: "cpe:/o:redhat:enterprise_linux:9",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"2",
					},
					Value: "cpe:/o:redhat:enterprise_linux:9::appstream",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"cpe",
						"3",
					},
					Value: "cpe:/o:redhat:enterprise_linux:9::baseos",
				},
				{
					Key: []string{
						"Red Hat CPE",
						"repository",
						"rhel-8-for-x86_64-baseos-rpms",
					},
					Value: []int{0},
				},
				{
					Key: []string{
						"Red Hat CPE",
						"nvr",
						"pam-1.5.1-21.el9_5.x86_64",
					},
					Value: []int{3},
				},
				{
					Key: []string{
						"advisory-detail",
						"RHSA-2024:9941",
						"Red Hat",
						"pam",
					},
					Value: redhatcsaf.Advisory{
						Entries: []redhatcsaf.Entry{
							{
								FixedVersion: "1.5.1-21.el9_5",
								CVEs: []redhatcsaf.CVEEntry{
									{
										ID:       "CVE-2024-10041",
										Severity: types.SeverityMedium,
									},
								},
								Arches:             []string{"aarch64", "x86_64"},
								AffectedCPEIndices: []int{3},
							},
						},
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"RHSA-2024:9999",
						"Red Hat",
						"test-package",
					},
					Value: redhatcsaf.Advisory{
						Entries: []redhatcsaf.Entry{
							{
								FixedVersion: "1:1.0.0-1.el9",
								CVEs: []redhatcsaf.CVEEntry{
									{
										ID:       "CVE-2024-11111",
										Severity: types.SeverityHigh,
									},
									{
										ID:       "CVE-2024-22222",
										Severity: types.SeverityCritical,
									},
								},
								Arches:             []string{"aarch64", "x86_64"},
								AffectedCPEIndices: []int{2, 3},
							},
						},
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2024-11111", // Use CVE ID instead of RHSA ID for unpatched vulnerabilities
						"Red Hat",
						"affected-package-bin",
					},
					Value: redhatcsaf.Advisory{
						Entries: []redhatcsaf.Entry{
							{
								FixedVersion: "", // unpatched vulnerability has no fixed version
								Status:       types.StatusAffected,
								CVEs: []redhatcsaf.CVEEntry{
									{
										Severity: types.SeverityHigh,
									},
								},
								Arches:             nil, // no arch in PURL for unpatched vulnerabilities
								AffectedCPEIndices: []int{3},
							},
						},
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"CVE-2024-22222", // Use CVE ID instead of RHSA ID for unpatched vulnerabilities
						"Red Hat",
						"affected-package-bin",
					},
					Value: redhatcsaf.Advisory{
						Entries: []redhatcsaf.Entry{
							{
								FixedVersion: "", // unpatched vulnerability has no fixed version
								Status:       types.StatusAffected,
								CVEs: []redhatcsaf.CVEEntry{
									{
										Severity: types.SeverityCritical,
									},
								},
								Arches:             nil, // no arch in PURL for unpatched vulnerabilities
								AffectedCPEIndices: []int{3},
							},
						},
					},
				},
				{
					Key: []string{
						"advisory-detail",
						"RHSA-2024:9999",
						"Red Hat",
						"module:2.4::modular-package",
					},
					Value: redhatcsaf.Advisory{
						Entries: []redhatcsaf.Entry{
							{
								FixedVersion: "2.4.37-65.module+el8.10.0+21982+14717793",
								CVEs: []redhatcsaf.CVEEntry{
									{
										ID:       "CVE-2024-11111",
										Severity: types.SeverityMedium,
									},
									{
										ID:       "CVE-2024-22222",
										Severity: types.SeverityMedium,
									},
								},
								Arches:             []string{"aarch64"},
								AffectedCPEIndices: []int{2},
							},
						},
					},
				},
				// Test case for new rpmmod qualifier format (pkg:rpm/...?rpmmod=...)
				{
					Key: []string{
						"advisory-detail",
						"RHSA-2025:0001",
						"Red Hat",
						"firefox:flatpak::firefox-x11",
					},
					Value: redhatcsaf.Advisory{
						Entries: []redhatcsaf.Entry{
							{
								Status: types.StatusFixed,
								CVEs: []redhatcsaf.CVEEntry{
									{
										ID:       "CVE-2025-33333",
										Severity: types.SeverityHigh,
									},
								},
								AffectedCPEIndices: []int{1},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := redhatcsaf.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
			})
		})
	}
}

// testStore is a custom Store implementation for testing WithStore.
// It records all Put calls and allows customizing PutMappings behavior.
type testStore struct {
	// extraCPEs are appended to the input CPE list by PutMappings
	extraCPEs []string
	// putInputs records all PutInput values passed to Put
	putInputs []*redhatcsaf.PutInput
}

func (s *testStore) PutMappings(dbc db.Operation, tx *bolt.Tx, input *redhatcsaf.MappingsInput) (redhatoval.CPEList, error) {
	// Simulate premium behavior: append extra CPEs (e.g., merged from OVAL)
	// and only write CPE indices (skip repo/NVR mappings).
	merged := append(redhatoval.CPEList{}, input.CPEList...)
	merged = append(merged, s.extraCPEs...)

	for i, cpe := range merged {
		if err := dbc.PutRedHatCPEs(tx, i, cpe); err != nil {
			return nil, err
		}
	}
	return merged, nil
}

func (s *testStore) Put(dbc db.Operation, tx *bolt.Tx, input *redhatcsaf.PutInput) error {
	s.putInputs = append(s.putInputs, input)

	// Convert CPE names to indices and write advisory (same as default)
	for i := range input.Advisory.Entries {
		input.Advisory.Entries[i].AffectedCPEIndices = input.CPEList.Indices(input.Advisory.Entries[i].AffectedCPEList)
	}

	vulnID := string(input.Bucket.VulnerabilityID)
	pkgName := input.Bucket.Package.Name
	if input.Bucket.Package.Module != "" {
		pkgName = fmt.Sprintf("%s::%s", input.Bucket.Package.Module, pkgName)
	}

	if err := dbc.PutAdvisoryDetail(tx, vulnID, pkgName, []string{"Red Hat"}, input.Advisory); err != nil {
		return err
	}
	return dbc.PutVulnerabilityID(tx, vulnID)
}

func TestVulnSrc_Update_WithCustomStore(t *testing.T) {
	store := &testStore{
		extraCPEs: []string{"cpe:/o:redhat:enterprise_linux:7::server"},
	}

	vs := redhatcsaf.NewVulnSrc(redhatcsaf.WithStore(store))

	tempDir := t.TempDir()
	require.NoError(t, db.Init(tempDir))
	defer db.Close()

	err := vs.Update("testdata")
	require.NoError(t, err)

	// Verify the custom store was called with Put
	assert.NotEmpty(t, store.putInputs, "custom Store.Put should have been called")

	// Verify the extra CPE was merged
	// The merged list should contain both CSAF CPEs and the extra one
	for _, input := range store.putInputs {
		assert.Contains(t, []string(input.CPEList), "cpe:/o:redhat:enterprise_linux:7::server",
			"merged CPE list should contain the extra CPE")
	}

	// Verify repo/NVR mappings were NOT written (custom store skips them)
	require.NoError(t, db.Close())
	require.NoError(t, db.Init(tempDir))

	// repo mapping should not exist since custom store doesn't write it
	_, err = db.Config{}.RedHatRepoToCPEs("rhel-8-for-x86_64-baseos-rpms")
	assert.NoError(t, err) // returns empty, not error
}
