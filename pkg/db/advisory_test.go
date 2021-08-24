package db_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-db/pkg/types"
)

func TestConfig_ForEachAdvisory(t *testing.T) {
	type args struct {
		source  string
		pkgName string
	}
	tests := []struct {
		name     string
		args     args
		fixtures []string
		want     map[string]types.Advisory
		wantErr  string
	}{
		{
			name: "single bucket",
			args: args{
				source:  "GitHub Security Advisory Composer",
				pkgName: "symfony/symfony",
			},
			fixtures: []string{"testdata/fixtures/single-bucket.yaml"},
			want: map[string]types.Advisory{
				"CVE-2019-10909": {
					PatchedVersions:    []string{"4.2.7", "3.4.26"},
					VulnerableVersions: []string{">= 4.2.0, < 4.2.7", ">= 3.0.0, < 3.4.26"},
				},
				"CVE-2019-18889": {
					PatchedVersions:    []string{"4.3.8", "3.4.35"},
					VulnerableVersions: []string{">= 4.3.0, < 4.3.8", ">= 3.1.0, < 3.4.35"},
				},
			},
		},
		{
			name: "prefix scan",
			args: args{
				source:  "composer::",
				pkgName: "symfony/symfony",
			},
			fixtures: []string{"testdata/fixtures/multiple-buckets.yaml"},
			want: map[string]types.Advisory{
				"CVE-2019-10909": {
					PatchedVersions:    []string{"4.2.7"},
					VulnerableVersions: []string{">= 4.2.0, < 4.2.7"},
				},
				"CVE-2020-5275": {
					VulnerableVersions: []string{">= 4.4.0, < 4.4.7"},
				},
			},
		},
		{
			name: "non-existent bucket",
			args: args{
				source:  "non-existent",
				pkgName: "symfony/symfony",
			},
			fixtures: []string{"testdata/fixtures/single-bucket.yaml"},
			want:     map[string]types.Advisory{},
		},
		{
			name: "non-existent package",
			args: args{
				source:  "GitHub Security Advisory Composer",
				pkgName: "non-existent",
			},
			fixtures: []string{"testdata/fixtures/single-bucket.yaml"},
			want:     map[string]types.Advisory{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize DB
			dbtest.InitTestDB(t, tt.fixtures)
			defer db.Close()

			dbc := db.Config{}
			got, err := dbc.ForEachAdvisory(tt.args.source, tt.args.pkgName)

			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			assert.NoError(t, err)

			// Compare
			assert.Equal(t, len(tt.want), len(got))
			for cveID, g := range got {
				wantAdvisory, ok := tt.want[cveID]
				if !ok {
					assert.Fail(t, "no such key", "CVE-ID", cveID)
				}

				var gotAdvisory types.Advisory
				err = json.Unmarshal(g, &gotAdvisory)
				require.NoError(t, err)

				assert.Equal(t, wantAdvisory, gotAdvisory)
			}
		})
	}
}

func TestConfig_GetAdvisories(t *testing.T) {
	type args struct {
		source  string
		pkgName string
	}
	tests := []struct {
		name     string
		args     args
		fixtures []string
		want     []types.Advisory
		wantErr  string
	}{
		{
			name: "os package advisories",
			args: args{
				source:  "Red Hat Enterprise Linux 8",
				pkgName: "bind",
			},
			fixtures: []string{"testdata/fixtures/ospkg.yaml"},
			want: []types.Advisory{
				{
					VulnerabilityID: "CVE-2018-5745",
					FixedVersion:    "32:9.11.4-26.P2.el8",
				},
				{
					VulnerabilityID: "CVE-2020-8617",
					FixedVersion:    "32:9.11.13-5.el8_2",
				},
			},
		},
		{
			name: "library advisories",
			args: args{
				source:  "GitHub Security Advisory Composer",
				pkgName: "symfony/symfony",
			},
			fixtures: []string{"testdata/fixtures/single-bucket.yaml"},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2019-10909",
					PatchedVersions:    []string{"4.2.7", "3.4.26"},
					VulnerableVersions: []string{">= 4.2.0, < 4.2.7", ">= 3.0.0, < 3.4.26"},
				},
				{
					VulnerabilityID:    "CVE-2019-18889",
					PatchedVersions:    []string{"4.3.8", "3.4.35"},
					VulnerableVersions: []string{">= 4.3.0, < 4.3.8", ">= 3.1.0, < 3.4.35"},
				},
			},
		},
		{
			name: "prefix scan",
			args: args{
				source:  "composer::",
				pkgName: "symfony/symfony",
			},
			fixtures: []string{"testdata/fixtures/multiple-buckets.yaml"},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2019-10909",
					PatchedVersions:    []string{"4.2.7"},
					VulnerableVersions: []string{">= 4.2.0, < 4.2.7"},
				},
				{
					VulnerabilityID:    "CVE-2020-5275",
					VulnerableVersions: []string{">= 4.4.0, < 4.4.7"},
				},
			},
		},
		{
			name: "non-existent bucket",
			args: args{
				source:  "non-existent",
				pkgName: "symfony/symfony",
			},
			fixtures: []string{"testdata/fixtures/single-bucket.yaml"},
		},
		{
			name: "non-existent package",
			args: args{
				source:  "GitHub Security Advisory Composer",
				pkgName: "non-existent",
			},
			fixtures: []string{"testdata/fixtures/single-bucket.yaml"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize DB
			dbtest.InitTestDB(t, tt.fixtures)
			defer db.Close()

			dbc := db.Config{}
			got, err := dbc.GetAdvisories(tt.args.source, tt.args.pkgName)

			switch {
			case tt.wantErr != "":
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			default:
				assert.NoError(t, err)
			}

			// Compare
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}
