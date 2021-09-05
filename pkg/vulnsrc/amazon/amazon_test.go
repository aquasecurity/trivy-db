package amazon_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fixtures "github.com/aquasecurity/bolt-fixtures"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/amazon"
)

func TestMain(m *testing.M) {
	utils.Quiet = true
	os.Exit(m.Run())
}

func TestVulnSrc_Update(t *testing.T) {
	type wantKV struct {
		key   []string
		value interface{}
	}
	tests := []struct {
		name       string
		dir        string
		wantValues []wantKV
		wantErr    string
	}{
		{
			name: "happy path",
			dir:  filepath.Join("testdata", "happy"),
			wantValues: []wantKV{
				{
					key: []string{"advisory-detail", "CVE-2018-17456", "amazon linux 1", "git"},
					value: types.Advisory{
						FixedVersion: "2.14.5-1.59.amzn1",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2018-17456", "amazon linux 1", "git-debuginfo"},
					value: types.Advisory{
						FixedVersion: "1:2.14.5-1.59.amzn1",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-22543", "amazon linux 2", "kernel"},
					value: types.Advisory{
						FixedVersion: "4.14.243-185.433.amzn2",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2021-22543", "amazon linux 2", "kernel-headers"},
					value: types.Advisory{
						FixedVersion: "4.14.243-185.433.amzn2",
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2018-17456", "amazon"},
					value: types.VulnerabilityDetail{
						Severity:    3,
						Description: "Package updates are available for Amazon Linux AMI that fix the following vulnerabilities:\nCVE-2018-17456:\n\tGit before 2.14.5, 2.15.x before 2.15.3, 2.16.x before 2.16.5, 2.17.x before 2.17.2, 2.18.x before 2.18.1, and 2.19.x before 2.19.1 allows remote code execution during processing of a recursive &quot;git clone&quot; of a superproject if a .gitmodules file has a URL field beginning with a &#039;-&#039; character.\n1636619: \nCVE-2018-17456 git: arbitrary code execution via .gitmodules\n",
						References:  []string{"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-17456"},
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2021-22543", "amazon"},
					value: types.VulnerabilityDetail{
						Severity:    1,
						Description: "Package updates are available for Amazon Linux 2 that fix the following vulnerabilities:\nCVE-2021-22543:\n\tA flaw was found in the Linux kernel's KVM implementation, where improper handing of the VM_IO|VM_PFNMAP VMAs in KVM bypasses RO checks and leads to pages being freed while still accessible by the VMM and guest. This flaw allows users who can start and control a VM to read/write random pages of memory, resulting in local privilege escalation. The highest threat from this vulnerability is to confidentiality, integrity, and system availability.\n1965461: CVE-2021-22543 kernel: Improper handling of VM_IO|VM_PFNMAP vmas in KVM can bypass RO checks\n",
						References:  []string{"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22543"},
					},
				},
			},
		},
		{
			name:    "sad path",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "failed to decode Amazon JSON",
		},
		{
			name:    "no such directory",
			dir:     filepath.Join("testdata", "nosuch"),
			wantErr: "no such file or directory",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()

			err := db.Init(tempDir)
			require.NoError(t, err)
			defer db.Close()

			vs := amazon.NewVulnSrc()
			err = vs.Update(tt.dir)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.NoError(t, db.Close())

			for _, want := range tt.wantValues {
				dbtest.JSONEq(t, db.Path(tempDir), want.key, want.value)
			}
		})
	}
}

func TestVulnSrc_Get(t *testing.T) {
	tests := []struct {
		name     string
		fixtures []string
		version  string
		pkgName  string
		want     []types.Advisory
		wantErr  string
	}{
		{
			name:     "happy path",
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			version:  "1",
			pkgName:  "curl",
			want:     []types.Advisory{{VulnerabilityID: "CVE-2019-0001", FixedVersion: "0.1.2"}},
		},
		{
			name:     "no advisories are returned",
			fixtures: []string{"testdata/fixtures/happy.yaml"},
			version:  "2",
			pkgName:  "curl",
		},
		{
			name:     "GetAdvisories returns an error",
			version:  "1",
			pkgName:  "curl",
			fixtures: []string{"testdata/fixtures/sad.yaml"},
			wantErr:  "failed to unmarshal advisory JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := initDB(t, tt.fixtures)

			// Initialize DB
			require.NoError(t, db.Init(dir))
			defer db.Close()

			ac := amazon.NewVulnSrc()
			vuls, err := ac.Get(tt.version, tt.pkgName)

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

func initDB(t *testing.T, fixtureFiles []string) string {
	// Create a temp dir
	dir := t.TempDir()

	dbPath := db.Path(dir)
	dbDir := filepath.Dir(dbPath)
	err := os.MkdirAll(dbDir, 0700)
	require.NoError(t, err)

	// Load testdata into BoltDB
	loader, err := fixtures.New(dbPath, fixtureFiles)
	require.NoError(t, err)
	require.NoError(t, loader.Load())
	require.NoError(t, loader.Close())

	return dir
}
