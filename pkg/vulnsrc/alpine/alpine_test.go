package alpine_test

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/alpine"
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
					Key: []string{"data-source", "alpine 3.12"},
					Value: types.DataSource{
						ID:   vulnerability.Alpine,
						Name: "Alpine Secdb",
						URL:  "https://secdb.alpinelinux.org/",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2019-14904", "alpine 3.12", "ansible"},
					Value: types.Advisory{
						FixedVersion: "2.9.3-r0",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2019-14905", "alpine 3.12", "ansible"},
					Value: types.Advisory{
						FixedVersion: "2.9.3-r0",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2024-22195", "alpine 3.12", "ansible"},
					Value: types.Advisory{
						FixedVersion: "2.9.3-r0",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2017-2616", "alpine 3.12", "ansible"},
					Value: types.Advisory{
						FixedVersion: "2.9.3-r0",
					},
				},
				{
					Key: []string{"advisory-detail", "GHSA-f7r5-w49x-gxm3", "alpine 3.12", "ansible"},
					Value: types.Advisory{
						FixedVersion: "2.9.3-r0",
					},
				},
				{
					Key: []string{"advisory-detail", "GHSA-h6cc-rc6q-23j4", "alpine 3.12", "ansible"},
					Value: types.Advisory{
						FixedVersion: "2.9.3-r0",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2020-1737", "alpine 3.12", "ansible"},
					Value: types.Advisory{
						FixedVersion: "2.9.6-r0",
					},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2019-14904",
					},
					Value: map[string]any{},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2019-14905",
					},
					Value: map[string]any{},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2024-22195",
					},
					Value: map[string]any{},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2017-2616",
					},
					Value: map[string]any{},
				},
				{
					Key: []string{
						"vulnerability-id",
						"GHSA-f7r5-w49x-gxm3",
					},
					Value: map[string]any{},
				},
				{
					Key: []string{
						"vulnerability-id",
						"GHSA-h6cc-rc6q-23j4",
					},
					Value: map[string]any{},
				},
				{
					Key: []string{
						"vulnerability-id",
						"CVE-2020-1737",
					},
					Value: map[string]any{},
				},
			},
		},
		{
			name:    "sad path",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "failed to decode Alpine advisory",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := alpine.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
			})
		})
	}
}
