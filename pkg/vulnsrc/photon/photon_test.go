package photon

import (
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
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
					key: []string{"data-source", "Photon OS 3.0"},
					value: types.DataSource{
						ID:   vulnerability.Photon,
						Name: "Photon OS CVE metadata",
						URL:  "https://packages.vmware.com/photon/photon_cve_metadata/",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2019-0199", "Photon OS 3.0", "apache-tomcat"},
					value: types.Advisory{
						FixedVersion: "8.5.40-1.ph3",
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2019-0199", "photon"},
					value: types.VulnerabilityDetail{
						CvssScoreV3: 7.5,
					},
				},
				{
					key:   []string{"vulnerability-id", "CVE-2019-0199"},
					value: map[string]interface{}{},
				},
			},
		},
		{
			name:    "sad path (dir doesn't exist)",
			dir:     filepath.Join("testdata", "badpathdoesnotexist"),
			wantErr: "no such file or directory",
		},
		{
			name:    "sad path (failed to decode)",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "failed to decode Photon JSON",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()

			err := db.Init(tempDir)
			require.NoError(t, err)
			defer db.Close()

			vs := NewVulnSrc()
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

func TestVulnSrc_Get(t *testing.T) {
	tests := []struct {
		name     string
		fixtures []string
		release  string
		pkgName  string
		want     []types.Advisory
		wantErr  string
	}{
		{
			name:     "happy path",
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			release:  "1.0",
			pkgName:  "ansible",
			want: []types.Advisory{
				{
					VulnerabilityID: "CVE-2019-3828",
					FixedVersion:    "2.7.6-2.ph3",
				},
			},
		},
		{
			name:     "no advisories are returned",
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			release:  "2.0",
			pkgName:  "ansible",
			want:     nil,
		},
		{
			name:     "GetAdvisories returns an error",
			fixtures: []string{"testdata/fixtures/sad.yaml"},
			release:  "1.0",
			pkgName:  "ansible",
			wantErr:  "failed to unmarshal advisory JSON",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			ac := NewVulnSrc()
			vuls, err := ac.Get(tt.release, tt.pkgName)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, vuls)
		})
	}
}
