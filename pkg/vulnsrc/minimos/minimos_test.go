package minimos_test

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/minimos"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
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
					Key: []string{"data-source", "minimos"},
					Value: types.DataSource{
						ID:   vulnerability.MinimOS,
						Name: "MinimOS Security Data",
						URL:  "https://packages.mini.dev/advisories/secdb/security.json",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-1999-0289", "minimos", "apache2"},
					Value: types.Advisory{
						FixedVersion: "0",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2022-38126", "minimos", "binutils"},
					Value: types.Advisory{
						FixedVersion: "2.39-r1",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2022-38533", "minimos", "binutils"},
					Value: types.Advisory{
						FixedVersion: "2.39-r2",
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-1999-0289"},
					Value: map[string]any{},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2022-38126"},
					Value: map[string]any{},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2022-38533"},
					Value: map[string]any{},
				},
			},
		},
		{
			name:    "sad path",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "json decode error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := minimos.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
			})
		})
	}
}
