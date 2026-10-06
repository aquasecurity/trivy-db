package susecsaf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
)

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func TestVulnSrc_Update(t *testing.T) {
	tests := []struct {
		name       string
		dir        string
		dist       Distribution
		wantValues []vulnsrctest.WantValues
		wantErr    string
	}{
		{
			name: "happy path with SUSE Enterprise Linux",
			dir:  filepath.Join("testdata", "happy", "SUSE Enterprise Linux"),
			dist: SUSEEnterpriseLinux,
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"data-source", "SUSE Linux Enterprise 15.1"},
					Value: types.DataSource{
						ID:   vulnerability.SuseCSAF,
						Name: "SUSE CSAF",
						URL:  "https://ftp.suse.com/pub/projects/security/csaf/",
					},
				},
				{
					Key: []string{
						"advisory-detail", "SUSE-SU-2019:0048-2", "SUSE Linux Enterprise 15.1", "helm-mirror",
					},
					Value: types.Advisory{
						FixedVersion: "0.2.1-1.7.1",
					},
				},
				{
					Key: []string{"vulnerability-detail", "SUSE-SU-2019:0048-2", "suse-csaf"},
					Value: types.VulnerabilityDetail{
						Title:       "Security update for helm-mirror",
						Description: "This update for helm-mirror to version 0.2.1 fixes the following issues:\n\n\nSecurity issues fixed:\n\n- CVE-2018-16873: Fixed a remote command execution (bsc#1118897)\n- CVE-2018-16874: Fixed a directory traversal in 'go get' via curly braces in import path (bsc#1118898)\n- CVE-2018-16875: Fixed a CPU denial of service (bsc#1118899)\n\nNon-security issue fixed:\n\n- Update to v0.2.1 (bsc#1120762)\n- Include helm-mirror into the containers module (bsc#1116182)\n",
						References: []string{
							"https://www.suse.com/support/security/rating/",
							"https://ftp.suse.com/pub/projects/security/csaf/suse-su-2019_0048-2.json",
							"https://www.suse.com/support/update/announcement/2019/suse-su-20190048-2/",
							"https://lists.suse.com/pipermail/sle-security-updates/2019-July/005660.html",
							"https://bugzilla.suse.com/1116182",
							"https://bugzilla.suse.com/1118897",
							"https://bugzilla.suse.com/1118898",
							"https://bugzilla.suse.com/1118899",
							"https://bugzilla.suse.com/1120762",
							"https://www.suse.com/security/cve/CVE-2018-16873/",
							"https://www.suse.com/security/cve/CVE-2018-16874/",
							"https://www.suse.com/security/cve/CVE-2018-16875/",
						},
						Severity: types.SeverityHigh,
					},
				},
				{
					Key:   []string{"vulnerability-id", "SUSE-SU-2019:0048-2"},
					Value: map[string]any{},
				},
			},
		},
		{
			name:    "sad path (dir doesn't exist)",
			dir:     filepath.Join("testdata", "badPath"),
			dist:    OpenSUSE,
			wantErr: "no such file or directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := NewVulnSrc(tt.dist)
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
			})
		})
	}
}

func TestBuildInput(t *testing.T) {
	vs := NewVulnSrc(SUSEEnterpriseLinux)
	// product_tree.branches carries CPEs that csaf.Advisory rejects (unescaped "," and "+"),
	// as found in the live SUSE feed. They must not prevent the advisory from being processed.
	data := []byte(`{
  "document": {
    "title": "Security update for helm-mirror",
    "tracking": {"id": "SUSE-SU-2019:0048-2"},
    "notes": [{"category": "description", "text": "details"}],
    "references": [{"url": "https://example.com/advisory"}]
  },
  "product_tree": {
    "branches": [{
      "category": "vendor",
      "name": "SUSE",
      "branches": [
        {
          "category": "product_name",
          "name": "OES",
          "product": {
            "name": "OES",
            "product_id": "OES",
            "product_identification_helper": {"cpe": "cpe:/o:novell,inc:OES:23.4"}
          }
        },
        {
          "category": "product_name",
          "name": "qemu",
          "product": {
            "name": "qemu",
            "product_id": "qemu",
            "product_identification_helper": {"cpe": "cpe:2.3:a:qemu:qemu:1.0.0+:*:*:*:*:*:*:*"}
          }
        }
      ]
    }],
    "relationships": [
      {
        "full_product_name": {"product_id": "SUSE Linux Enterprise Module for Containers 15 SP1:helm-mirror-0:0.2.1-1.7.1.x86_64"},
        "product_reference": "helm-mirror-0:0.2.1-1.7.1.x86_64",
        "relates_to_product_reference": "SUSE Linux Enterprise Module for Containers 15 SP1"
      },
      {
        "full_product_name": {"product_id": "SUSE Linux Enterprise Module for Containers 15 SP1:helm-mirror-0:0.2.1-1.7.1.aarch64"},
        "product_reference": "helm-mirror-0:0.2.1-1.7.1.aarch64",
        "relates_to_product_reference": "SUSE Linux Enterprise Module for Containers 15 SP1"
      },
      {
        "full_product_name": {"product_id": "sles-15-sp1-epoch-pkg"},
        "product_reference": "epoch-pkg-2:1.0-1.1.noarch",
        "relates_to_product_reference": "SUSE Linux Enterprise Server 15 SP1"
      },
      {
        "full_product_name": {"product_id": "SUSE Linux Enterprise Server 15 SP1:not-listed-1.0-1.1.noarch"},
        "product_reference": "not-listed-1.0-1.1.noarch",
        "relates_to_product_reference": "SUSE Linux Enterprise Server 15 SP1"
      }
    ]
  },
  "vulnerabilities": [{
    "product_status": {
      "recommended": [
        "SUSE Linux Enterprise Module for Containers 15 SP1:helm-mirror-0:0.2.1-1.7.1.x86_64",
        "SUSE Linux Enterprise Module for Containers 15 SP1:helm-mirror-0:0.2.1-1.7.1.aarch64",
        "sles-15-sp1-epoch-pkg"
      ]
    },
    "threats": [{"category": "impact", "details": "important"}]
  }]
}`)
	var adv Advisory
	require.NoError(t, json.Unmarshal(data, &adv))

	input, err := vs.buildInput(adv)
	require.NoError(t, err)
	assert.Equal(t, "SUSE-SU-2019:0048-2", input.VulnID)
	assert.Equal(t, "Security update for helm-mirror", input.Vuln.Title)
	assert.Equal(t, "details", input.Vuln.Description)
	assert.Equal(t, types.SeverityHigh, input.Vuln.Severity)

	// - arches are collapsed into one package and the zero epoch is dropped;
	// - the product ID is taken from full_product_name, even when it isn't "<platform>:<reference>";
	// - products missing from product_status are skipped.
	assert.Equal(t, []AffectedPackage{
		{
			OSVer:   "SUSE Linux Enterprise 15.1",
			Package: Package{Name: "helm-mirror", FixedVersion: "0.2.1-1.7.1"},
		},
		{
			OSVer:   "SUSE Linux Enterprise 15.1",
			Package: Package{Name: "epoch-pkg", FixedVersion: "2:1.0-1.1"},
		},
	}, input.AffectedPkgs)
}

func TestBuildInput_NoVulnerabilities(t *testing.T) {
	vs := NewVulnSrc(SUSEEnterpriseLinux)
	// Some advisories have no vulnerabilities section (e.g. SUSE-SU-2022:1714-1): every
	// relationship is used and the severity falls back to document.aggregate_severity.
	data := []byte(`{
  "document": {
    "title": "Security update for php72",
    "tracking": {"id": "SUSE-SU-2022:1714-1"},
    "aggregate_severity": {"text": "moderate"}
  },
  "product_tree": {
    "relationships": [{
      "full_product_name": {"product_id": "SUSE Linux Enterprise Server 12 SP5:php72-7.2.5-1.81.1.x86_64"},
      "product_reference": "php72-7.2.5-1.81.1.x86_64",
      "relates_to_product_reference": "SUSE Linux Enterprise Server 12 SP5"
    }]
  }
}`)
	var adv Advisory
	require.NoError(t, json.Unmarshal(data, &adv))

	input, err := vs.buildInput(adv)
	require.NoError(t, err)
	assert.Equal(t, types.SeverityMedium, input.Vuln.Severity)
	assert.Equal(t, []AffectedPackage{
		{
			OSVer:   "SUSE Linux Enterprise 12.5",
			Package: Package{Name: "php72", FixedVersion: "7.2.5-1.81.1"},
		},
	}, input.AffectedPkgs)
}

func TestVulnSrc_Get(t *testing.T) {
	tests := []struct {
		name     string
		fixtures []string
		version  string
		pkgName  string
		dist     Distribution
		want     []types.Advisory
		wantErr  string
	}{
		{
			name:     "happy path",
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			version:  "13.1",
			pkgName:  "bind",
			dist:     OpenSUSE,
			want: []types.Advisory{
				{
					VulnerabilityID: "openSUSE-SU-2019:0003-1",
					FixedVersion:    "1.3.29-bp150.2.12.1",
				},
			},
		},
		{
			name:     "no advisories are returned",
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			version:  "15.1",
			pkgName:  "bind",
			dist:     OpenSUSE,
			want:     nil,
		},
		{
			name:     "GetAdvisories returns an error",
			fixtures: []string{"testdata/fixtures/sad.yaml"},
			version:  "13.1",
			pkgName:  "bind",
			dist:     OpenSUSE,
			wantErr:  "json unmarshal error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := NewVulnSrc(tt.dist)
			vulnsrctest.TestGet(t, vs, vulnsrctest.TestGetArgs{
				Fixtures:   tt.fixtures,
				WantValues: tt.want,
				GetParams: db.GetParams{
					Release: tt.version,
					PkgName: tt.pkgName,
				},
				WantErr: tt.wantErr,
			})
		})
	}
}

func TestStripArchSuffix(t *testing.T) {
	tests := map[string]string{
		"helm-mirror-0.2.1-1.7.1.x86_64": "helm-mirror-0.2.1-1.7.1",
		"pkg-1.2.3.aarch64":              "pkg-1.2.3",
		"pkg-1.0.noarch":                 "pkg-1.0",
		"pkg-1.0.ia64":                   "pkg-1.0",
		"pkg-1.0.aarch64_ilp32":          "pkg-1.0",
		"pkg-1.0.i686":                   "pkg-1.0",
		"pkg-1.2.3":                      "pkg-1.2.3",
	}
	for in, want := range tests {
		assert.Equal(t, want, stripArchSuffix(in))
	}
}

func Test_splitPkgName(t *testing.T) {
	tests := []struct {
		pkgName        string
		wantPkgName    string
		wantPkgVersion string
	}{
		{
			pkgName:        "helm-mirror-0.2.1-1.7.1",
			wantPkgName:    "helm-mirror",
			wantPkgVersion: "0.2.1-1.7.1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.pkgName, func(t *testing.T) {
			gotPkgName, gotPkgVersion := splitPkgName(tt.pkgName)
			assert.Equal(t, tt.wantPkgName, gotPkgName)
			assert.Equal(t, tt.wantPkgVersion, gotPkgVersion)
		})
	}
}
