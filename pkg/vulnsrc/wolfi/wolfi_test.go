package wolfi_test

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/wolfi"
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
					Key: []string{"data-source", "wolfi"},
					Value: types.DataSource{
						ID:   vulnerability.Wolfi,
						Name: "Wolfi Secdb",
						URL:  "https://packages.wolfi.dev/os/security.json",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2022-38126", "wolfi", "binutils"},
					Value: types.Advisory{
						FixedVersion: "2.39-r1",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2022-38533", "wolfi", "binutils"},
					Value: types.Advisory{
						FixedVersion: "2.39-r2",
					},
				},
			},
		},
		{
			name:    "sad path",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "failed to decode Wolfi advisory",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := wolfi.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
			})
		})
	}
}
