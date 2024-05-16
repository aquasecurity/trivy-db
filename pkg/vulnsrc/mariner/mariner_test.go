package mariner_test

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
	cbl "github.com/aquasecurity/trivy-db/pkg/vulnsrc/mariner"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
)

func TestVulnSrc_Update(t *testing.T) {
	tests := []struct {
		name       string
		dir        string
		wantValues []vulnsrctest.WantValues
		wantErr    string
		noBuckets  [][]string
	}{
		{
			name: "happy path",
			dir:  filepath.Join("testdata", "happy"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"data-source", "CBL-Mariner 1.0"},
					Value: types.DataSource{
						ID:   vulnerability.CBLMariner,
						Name: "CBL-Mariner Vulnerability Data",
						URL:  "https://github.com/microsoft/CBL-MarinerVulnerabilityData",
					},
				},
				{
					Key: []string{"data-source", "CBL-Mariner 2.0"},
					Value: types.DataSource{
						ID:   vulnerability.CBLMariner,
						Name: "CBL-Mariner Vulnerability Data",
						URL:  "https://github.com/microsoft/CBL-MarinerVulnerabilityData",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2008-3914", "CBL-Mariner 1.0", "clamav"},
					Value: types.Advisory{
						FixedVersion: "0:0.103.2-1.cm1",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2021-39924", "CBL-Mariner 2.0", "wireshark"},
					Value: types.Advisory{
						FixedVersion: "",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2023-5678", "CBL-Mariner 2.0", "openssl"},
					Value: types.Advisory{
						FixedVersion: "0:1.1.1k-28.cm2",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2023-5678", "CBL-Mariner 2.0", "edk2"},
					Value: types.Advisory{
						FixedVersion: "0:20230301gitf80f052277c8-38.cm2",
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2008-3914", "cbl-mariner"},
					Value: types.VulnerabilityDetail{
						Severity:    types.SeverityCritical,
						Title:       "CVE-2008-3914 affecting package clamav 0.101.2",
						Description: "CVE-2008-3914 affecting package clamav 0.101.2. An upgraded version of the package is available that resolves this issue.",
						References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2008-3914"},
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2021-39924", "cbl-mariner"},
					Value: types.VulnerabilityDetail{
						Severity:    types.SeverityHigh,
						Title:       "CVE-2021-39924 affecting package wireshark 3.4.4",
						Description: "CVE-2021-39924 affecting package wireshark 3.4.4. No patch is available currently.",
						References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-39924"},
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2023-5678", "cbl-mariner"},
					Value: types.VulnerabilityDetail{
						Severity:    types.SeverityMedium,
						Title:       "CVE-2023-5678 affecting package openssl for versions less than 1.1.1k-28",
						Description: "CVE-2023-5678 affecting package openssl for versions less than 1.1.1k-28. A patched version of the package is available.",
						References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-5678"},
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2008-3914"},
					Value: map[string]interface{}{},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2021-39924"},
					Value: map[string]interface{}{},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2023-5678"},
					Value: map[string]interface{}{},
				},
			},
		},
		{
			name: "happy path not applicable",
			dir:  filepath.Join("testdata", "not-applicable-definition"),
			noBuckets: [][]string{
				{"advisory-detail"},
				{"vulnerability-id"},
				{"vulnerability-detail"},
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
			vs := cbl.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
				NoBuckets:  tt.noBuckets,
			})
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
			vs := cbl.NewVulnSrc()
			vulnsrctest.TestGet(t, vs, vulnsrctest.TestGetArgs{
				Fixtures:   tt.fixtures,
				WantValues: tt.want,
				Release:    tt.release,
				PkgName:    tt.pkgName,
				WantErr:    tt.wantErr,
			})
		})
	}
}
