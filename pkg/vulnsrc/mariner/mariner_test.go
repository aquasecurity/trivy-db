package mariner_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-db/pkg/types"
	cbl "github.com/aquasecurity/trivy-db/pkg/vulnsrc/mariner"
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
						Name: "CBL-Mariner Vulnerability Data",
						URL:  "https://github.com/microsoft/CBL-MarinerVulnerabilityData",
					},
				},
				{
					key: []string{"data-source", "CBL-Mariner 2.0"},
					value: types.DataSource{
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
			name:    "sad path",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "failed to parse CBL-Mariner OVAL: failed to parse ovalTests: failed to parse objects",
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
