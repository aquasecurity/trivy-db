package chainguard_test

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/chainguard"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
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
					Key: []string{"data-source", "chainguard"},
					Value: types.DataSource{
						ID:   vulnerability.Chainguard,
						Name: "Chainguard Security Data",
						URL:  "https://packages.cgr.dev/chainguard/security.json",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2022-38126", "chainguard", "binutils"},
					Value: types.Advisory{
						FixedVersion: "2.39-r1",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2022-38533", "chainguard", "binutils"},
					Value: types.Advisory{
						FixedVersion: "2.39-r2",
					},
				},
			},
		},
		{
			name:    "sad path",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "failed to decode Chainguard advisory",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := chainguard.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
			})
		})
	}
}
