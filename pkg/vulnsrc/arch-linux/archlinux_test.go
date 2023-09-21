package archlinux

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
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
					Key: []string{"data-source", "archlinux"},
					Value: types.DataSource{
						ID:   vulnerability.ArchLinux,
						Name: "Arch Linux Vulnerable issues",
						URL:  "https://security.archlinux.org/",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2019-11479", "archlinux", "linux-lts"},
					Value: types.Advisory{
						FixedVersion:    "4.19.52-1",
						AffectedVersion: "4.19.51-1",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2019-11478", "archlinux", "linux-lts"},
					Value: types.Advisory{
						FixedVersion:    "4.19.52-1",
						AffectedVersion: "4.19.51-1",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2019-11477", "archlinux", "linux-lts"},
					Value: types.Advisory{
						FixedVersion:    "4.19.52-1",
						AffectedVersion: "4.19.51-1",
					},
				},
			},
		},
		{
			name:    "sad path",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "failed to decode arch linux json",
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
