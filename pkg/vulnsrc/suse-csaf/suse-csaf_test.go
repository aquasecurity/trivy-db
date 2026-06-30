package susecsaf

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

func TestDecodeAdvisory_CSAF(t *testing.T) {
	data := []byte(`{
  "document": {
    "title": "Security update for helm-mirror",
    "tracking": {"id": "SUSE-SU-2019:0048-2"},
    "notes": [{"category": "description", "text": "details"}],
    "references": [{"url": "https://example.com/advisory"}]
  },
  "product_tree": {
    "relationships": [{
      "product_reference": "helm-mirror-0.2.1-1.7.1.x86_64",
      "relates_to_product_reference": "SUSE Linux Enterprise Module for Containers 15 SP1"
    }]
  },
  "vulnerabilities": [{
    "threats": [{"category": "impact", "details": "important"}]
  }]
}`)
	adv, err := decodeAdvisory(bytes.NewReader(data))
	require.NoError(t, err)
	assert.Equal(t, "SUSE-SU-2019:0048-2", adv.Tracking.ID)
	assert.Equal(t, "Security update for helm-mirror", adv.Title)
	assert.Len(t, adv.ProductTree.Relationships, 1)
	assert.Equal(t, "helm-mirror-0.2.1-1.7.1.x86_64", adv.ProductTree.Relationships[0].ProductReference)
	assert.Len(t, adv.Vulnerabilities, 1)
	assert.Equal(t, "important", adv.Vulnerabilities[0].Threats[0].Severity)
}

func TestStripArchSuffix(t *testing.T) {
	tests := map[string]string{
		"helm-mirror-0.2.1-1.7.1.x86_64": "helm-mirror-0.2.1-1.7.1",
		"pkg-1.2.3.aarch64":              "pkg-1.2.3",
		"pkg-1.2.3":                      "pkg-1.2.3",
	}
	for in, want := range tests {
		assert.Equal(t, want, stripArchSuffix(in))
	}
}

func Test_splitPkgName(t *testing.T) {
	tests := []struct {
		pkgName         string
		wantPkgName     string
		wantPkgVersion  string
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
