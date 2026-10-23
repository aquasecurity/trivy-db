package chainguard_test

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/chainguard"
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
			name: "same CVE listed under multiple fixed versions",
			dir:  filepath.Join("testdata", "multi-version"),
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
					Key: []string{"advisory-detail", "CVE-2025-4432", "chainguard", "cargo-audit"},
					Value: types.Advisory{
						FixedVersion: "0.21.2-r4",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2025-99999", "chainguard", "cargo-audit"},
					Value: types.Advisory{
						FixedVersion: "0.21.2-r4",
					},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2025-4432"},
					Value: map[string]any{},
				},
				{
					Key:   []string{"vulnerability-id", "CVE-2025-99999"},
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
			vs := chainguard.NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
			})
		})
	}
}

// The same input must always produce the same advisory, whichever order the
// secfixes map happens to be iterated in. On the unfixed code the advisory
// below flips between the two listed fixed versions, so one of the rounds
// fails.
// See https://github.com/aquasecurity/trivy-db/issues/699
func TestVulnSrc_UpdateDeterministic(t *testing.T) {
	vs := chainguard.NewVulnSrc()
	for i := 0; i < 20; i++ {
		vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
			Dir: filepath.Join("testdata", "multi-version"),
			WantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"advisory-detail", "CVE-2025-4432", "chainguard", "cargo-audit"},
					Value: types.Advisory{
						FixedVersion: "0.21.2-r4",
					},
				},
			},
		})
	}
}
