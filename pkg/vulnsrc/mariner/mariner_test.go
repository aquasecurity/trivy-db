package mariner_test

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/mariner"
	cbl "github.com/aquasecurity/trivy-db/pkg/vulnsrc/mariner"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

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
			dir:  filepath.Join("testdata", "happy"),
			wantValues: []want{
				{
					key: []string{"data-source", "CBL-Mariner 1.0"},
					value: types.DataSource{
						ID:   vulnerability.CBLMariner,
						Name: "CBL-Mariner Vulnerability Data",
						URL:  "https://github.com/microsoft/CBL-MarinerVulnerabilityData",
					},
				},
				{
					key: []string{"data-source", "CBL-Mariner 2.0"},
					value: types.DataSource{
						ID:   vulnerability.CBLMariner,
						Name: "CBL-Mariner Vulnerability Data",
						URL:  "https://github.com/microsoft/CBL-MarinerVulnerabilityData",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2008-3914", "CBL-Mariner 1.0", "clamav"},
					value: types.Advisory{
						FixedVersion: "0:0.103.2-1.cm1",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-39924", "CBL-Mariner 2.0", "wireshark"},
					value: types.Advisory{
						FixedVersion: "",
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2008-3914", "cbl-mariner"},
					value: types.VulnerabilityDetail{
						Severity:    types.SeverityCritical,
						Title:       "CVE-2008-3914 affecting package clamav 0.101.2",
						Description: "CVE-2008-3914 affecting package clamav 0.101.2. An upgraded version of the package is available that resolves this issue.",
						References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2008-3914"},
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2021-39924", "cbl-mariner"},
					value: types.VulnerabilityDetail{
						Severity:    types.SeverityHigh,
						Title:       "CVE-2021-39924 affecting package wireshark 3.4.4",
						Description: "CVE-2021-39924 affecting package wireshark 3.4.4. No patch is available currently.",
						References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-39924"},
					},
				},
				{
					key:   []string{"vulnerability-id", "CVE-2008-3914"},
					value: map[string]interface{}{},
				},
				{
					key:   []string{"vulnerability-id", "CVE-2021-39924"},
					value: map[string]interface{}{},
				},
			},
		},
		{
			name:    "sad path invalid objects",
			dir:     filepath.Join("testdata", "sad", "invalid-objects"),
			wantErr: "failed to parse objects",
		},
		{
			name:    "sad path invalid states",
			dir:     filepath.Join("testdata", "sad", "invalid-states"),
			wantErr: "failed to parse states",
		},
		{
			name:    "sad path invalid tests",
			dir:     filepath.Join("testdata", "sad", "invalid-tests"),
			wantErr: "failed to parse tests",
		},
		{
			name:    "sad path empty test ref definition",
			dir:     filepath.Join("testdata", "sad", "empty-testref-definition"),
			wantErr: "",
		},
		{
			name:    "sad path empty state ref tests",
			dir:     filepath.Join("testdata", "sad", "empty-stateref-tests"),
			wantErr: "unable to follow test refs: invalid test, no state ref",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()

			err := db.Init(tempDir)
			require.NoError(t, err)
			defer db.Close()

			vs := cbl.NewVulnSrc()
			err = vs.Update(tt.dir)
			if tt.wantErr != "" {
				require.Error(t, err)
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
		release  string
		pkgName  string
		fixtures []string
		want     []types.Advisory
		wantErr  string
	}{
		{
			name:     "happy path",
			release:  "1.0",
			pkgName:  "clamav",
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			want: []types.Advisory{
				{
					VulnerabilityID: "CVE-2008-3914",
					FixedVersion:    "0:0.103.2-1.cm1",
				},
			},
		},
		{
			name:     "happy path non fixed version",
			release:  "2.0",
			pkgName:  "bind",
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			want: []types.Advisory{
				{
					VulnerabilityID: "CVE-2019-6470",
				},
			},
		},
		{
			name:     "unknown package",
			release:  "2.0",
			pkgName:  "unknown-package",
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			want:     []types.Advisory(nil),
		},
		{
			name:     "broken bucket",
			release:  "1.0",
			pkgName:  "clamav",
			fixtures: []string{"testdata/fixtures/broken.yaml"},
			wantErr:  "failed to unmarshal advisory JSON",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			vs := mariner.NewVulnSrc()
			got, err := vs.Get(tt.release, tt.pkgName)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			sort.Slice(got, func(i, j int) bool {
				return got[i].VulnerabilityID < got[j].VulnerabilityID
			})

			// Compare
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
