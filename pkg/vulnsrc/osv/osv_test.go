package osv

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOsv(t *testing.T) {
	type want struct {
		key                []string
		valueAdvisory      types.Advisory
		valueVulnerability types.VulnerabilityDetail
	}
	tests := []struct {
		name      string
		ecosystem string
		dir       string
		wantValue []want
		wantErr   string
	}{
		{
			name:      "single range version and references PyPI",
			ecosystem: "PyPI",
			dir:       filepath.Join("testdata", "singlerange"),
			wantValue: []want{
				{
					key: []string{"advisory-detail", "CVE-2018-10895", "Osv Security Advisories PyPI", "qutebrowser"},
					valueAdvisory: types.Advisory{
						VulnerableVersions: []string{">=0 <1.4.1"},
						PatchedVersions:    []string{"1.4.1"},
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2018-10895", "osv-pypi"},
					valueVulnerability: types.VulnerabilityDetail{
						ID:               "CVE-2018-10895",
						Description:      "qutebrowser before version 1.4.1 is vulnerable to a cross-site request forgery flaw that allows websites to access 'qute://*' URLs. A malicious website could exploit this to load a 'qute://settings/set' URL, which then sets 'editor.command' to a bash script, resulting in arbitrary code execution.",
						PublishedDate:    MustParse(time.RFC3339, "2018-07-12T12:29:00Z"),
						LastModifiedDate: MustParse(time.RFC3339Nano, "2021-06-10T06:51:37.378319Z"),
						Title:            "PYSEC-2018-27",
						References:       []string{"https://github.com/qutebrowser/qutebrowser/commit/43e58ac865ff862c2008c510fc5f7627e10b4660"},
					},
				},
			},
		},
		{
			name:      "single range version and references Go",
			ecosystem: "Go",
			dir:       filepath.Join("testdata", "singlerange"),
			wantValue: []want{
				{
					key: []string{"advisory-detail", "CVE-2017-18367", "Osv Security Advisories Go", "github.com/seccomp/libseccomp-golang"},
					valueAdvisory: types.Advisory{
						VulnerableVersions: []string{">=0 <0.9.1-0.20170424173420-06e7a29f36a3"},
						PatchedVersions:    []string{"0.9.1-0.20170424173420-06e7a29f36a3"},
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2017-18367", "osv-go"},
					valueVulnerability: types.VulnerabilityDetail{
						ID:               "CVE-2017-18367",
						Description:      "Filters containing rules with multiple syscall arguments are improperly\nconstructed, such that all arguments are required to match rather than\nany of the arguments (AND is used rather than OR). These filters can be\nbypassed by only specifying a subset of the arguments due to this\nbehavior.\n",
						PublishedDate:    MustParse(time.RFC3339, "2021-04-14T12:00:00Z"),
						LastModifiedDate: MustParse(time.RFC3339Nano, "2021-04-14T12:00:00Z"),
						Title:            "GO-2020-0007",
						References:       []string{"https://github.com/seccomp/libseccomp-golang/commit/06e7a29f36a34b8cf419aeb87b979ee508e58f9e"},
					},
				},
			},
		},
		{
			name:      "single range version and references crates.io",
			ecosystem: "crates.io",
			dir:       filepath.Join("testdata", "singlerange"),
			wantValue: []want{
				{
					key: []string{"advisory-detail", "CVE-2020-36214", "Osv Security Advisories crates.io", "multiqueue2"},
					valueAdvisory: types.Advisory{
						VulnerableVersions: []string{">=0.0.0-0 <0.1.7"},
						PatchedVersions:    []string{"0.1.7"},
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2020-36214", "osv-crates.io"},
					valueVulnerability: types.VulnerabilityDetail{
						ID:               "CVE-2020-36214",
						Description:      "Affected versions of this crate unconditionally implemented `Send` for types used in queue implementations (`InnerSend\u003cRW, T\u003e`, `InnerRecv\u003cRW, T\u003e`, `FutInnerSend\u003cRW, T\u003e`, `FutInnerRecv\u003cRW, T\u003e`).\n\nThis allows users to send non-Send types to other threads, which can lead to data race bugs or other undefined behavior.\n\nThe flaw was corrected in v0.1.7 by adding `T: Send` bound to to the `Send` impl of four data types explained above.",
						PublishedDate:    MustParse(time.RFC3339, "2020-12-19T12:00:00Z"),
						LastModifiedDate: MustParse(time.RFC3339Nano, "2021-10-19T22:14:35Z"),
						Title:            "RUSTSEC-2020-0106",
						References:       []string{"https://crates.io/crates/multiqueue2"},
					},
				},
			},
		},
		{
			name:      "no introduced, have versions PyPI",
			ecosystem: "PyPI",
			dir:       filepath.Join("testdata", "nointroduced"),
			wantValue: []want{
				{
					key: []string{"advisory-detail", "CVE-2010-2970", "Osv Security Advisories PyPI", "moin"},
					valueAdvisory: types.Advisory{
						VulnerableVersions: []string{">=1.9.0 <1.9.3"},
						PatchedVersions:    []string{"1.9.3"},
					},
				},
			},
		},
		{
			name:      "no introduced, no versions crates.io",
			ecosystem: "crates.io",
			dir:       filepath.Join("testdata", "nointroduced"),
			wantValue: []want{
				{
					key: []string{"advisory-detail", "CVE-2019-15554", "Osv Security Advisories crates.io", "smallvec"},
					valueAdvisory: types.Advisory{
						VulnerableVersions: []string{">=0.0.0-0 <0.6.10"},
						PatchedVersions:    []string{"0.6.10"},
					},
				},
			},
		},
		{
			name:      "multi range version and references PyPI",
			ecosystem: "PyPI",
			dir:       filepath.Join("testdata", "multirange"),
			wantValue: []want{
				{
					key: []string{"advisory-detail", "CVE-2021-33571", "Osv Security Advisories PyPI", "django"},
					valueAdvisory: types.Advisory{
						VulnerableVersions: []string{">=2.2 <2.2.24", ">=3.0 <3.1.12", ">=3.2 <3.2.4"},
						PatchedVersions:    []string{"2.2.24", "3.1.12", "3.2.4"},
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2021-33571", "osv-pypi"},
					valueVulnerability: types.VulnerabilityDetail{
						ID:               "CVE-2021-33571",
						Description:      "In Django 2.2 before 2.2.24, 3.x before 3.1.12, and 3.2 before 3.2.4, URLValidator, validate_ipv4_address, and validate_ipv46_address do not prohibit leading zero characters in octal literals. This may allow a bypass of access control that is based on IP addresses. (validate_ipv4_address and validate_ipv46_address are unaffected with Python 3.9.5+..) .",
						PublishedDate:    MustParse(time.RFC3339, "2021-06-08T18:15:00Z"),
						LastModifiedDate: MustParse(time.RFC3339Nano, "2021-06-22T04:54:55.488063Z"),
						Title:            "PYSEC-2021-99",
						References: []string{
							"https://groups.google.com/g/django-announce/c/sPyjSKMi8Eo",
							"https://docs.djangoproject.com/en/3.2/releases/security/",
							"https://www.djangoproject.com/weblog/2021/jun/02/security-releases/",
						},
					},
				},
			},
		},
		{
			name:      "multi range version and references Go",
			ecosystem: "Go",
			dir:       filepath.Join("testdata", "multirange"),
			wantValue: []want{
				{
					key: []string{"advisory-detail", "CVE-2020-28362", "Osv Security Advisories Go", "math/big"},
					valueAdvisory: types.Advisory{
						VulnerableVersions: []string{">=1.14 <1.14.12", ">=1.15 <1.15.5"},
						PatchedVersions:    []string{"1.14.12", "1.15.5"},
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2020-28362", "osv-go"},
					valueVulnerability: types.VulnerabilityDetail{
						ID:               "CVE-2020-28362",
						Description:      "A number of math/big.Int methods can panic when provided large inputs due\nto a flawed division method.\n",
						PublishedDate:    MustParse(time.RFC3339, "2021-04-14T12:00:00Z"),
						LastModifiedDate: MustParse(time.RFC3339Nano, "2021-04-14T12:00:00Z"),
						Title:            "GO-2021-0069",
						References: []string{
							"https://go-review.googlesource.com/c/go/+/269657",
							"https://github.com/golang/go/commit/1e1fa5903b760c6714ba17e50bf850b01f49135c",
							"https://github.com/golang/go/issues/42552",
						},
					},
				},
			},
		},
		{
			name:      "multi range version and references crates.io",
			ecosystem: "crates.io",
			dir:       filepath.Join("testdata", "multirange"),
			wantValue: []want{
				{
					key: []string{"advisory-detail", "CVE-2017-18587", "Osv Security Advisories crates.io", "hyper"},
					valueAdvisory: types.Advisory{
						VulnerableVersions: []string{">=0.0.0-0 <0.9.18", ">=0.10.0 <0.10.2"},
						PatchedVersions:    []string{"0.9.18", "0.10.2"},
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2017-18587", "osv-crates.io"},
					valueVulnerability: types.VulnerabilityDetail{
						ID:               "CVE-2017-18587",
						Description:      "Serializing of headers to the socket did not filter the values for newline bytes (`\\r` or `\\n`),\nwhich allowed for header values to split a request or response. People would not likely include\nnewlines in the headers in their own applications, so the way for most people to exploit this\nis if an application constructs headers based on unsanitized user input.\n\nThis issue was fixed by replacing all newline characters with a space during serialization of\na header value.",
						PublishedDate:    MustParse(time.RFC3339, "2017-01-23T12:00:00Z"),
						LastModifiedDate: MustParse(time.RFC3339Nano, "2021-10-19T22:14:35Z"),
						Title:            "RUSTSEC-2017-0002",
						References: []string{
							"https://crates.io/crates/hyper",
							"https://rustsec.org/advisories/RUSTSEC-2017-0002.html",
							"https://github.com/hyperium/hyper/wiki/Security-001",
						},
					},
				},
			},
		},
		{
			name:      "some fixed successively Go",
			ecosystem: "Go",
			dir:       filepath.Join("testdata", "somefixedsuccessively"),
			wantValue: []want{
				{
					key: []string{"advisory-detail", "CVE-2021-3115", "Osv Security Advisories Go", "cmd/go"},
					valueAdvisory: types.Advisory{
						VulnerableVersions: []string{">=0 <1.14.14 <1.15.7"},
						PatchedVersions:    []string{"1.14.14", "1.15.7"},
					},
				},
			},
		},
		{
			name:      "some package in file",
			ecosystem: "Go",
			dir:       filepath.Join("testdata", "somepackages"),
			wantValue: []want{
				{
					key: []string{"advisory-detail", "GO-2020-0024", "Osv Security Advisories Go", "github.com/btcsuite/go-socks/socks"},
					valueAdvisory: types.Advisory{
						VulnerableVersions: []string{">=0 <0.0.0-20130808000456-233bccbb1abe"},
						PatchedVersions:    []string{"0.0.0-20130808000456-233bccbb1abe"},
					},
				},
				{
					key: []string{"advisory-detail", "GO-2020-0024", "Osv Security Advisories Go", "github.com/btcsuitereleases/go-socks/socks"},
					valueAdvisory: types.Advisory{
						VulnerableVersions: []string{">=0 <0.0.0-20130808000456-233bccbb1abe"},
						PatchedVersions:    []string{"0.0.0-20130808000456-233bccbb1abe"},
					},
				},
				{
					key: []string{"vulnerability-detail", "GO-2020-0024", "osv-go"},
					valueVulnerability: types.VulnerabilityDetail{
						ID:               "GO-2020-0024",
						Description:      "The RemoteAddr and LocalAddr methods on the returned net.Conn may\ncall themselves, leading to an infinite loop which will crash the\nprogram due to a stack overflow.\n",
						PublishedDate:    MustParse(time.RFC3339, "2021-04-14T12:00:00Z"),
						LastModifiedDate: MustParse(time.RFC3339Nano, "2021-04-14T12:00:00Z"),
						Title:            "GO-2020-0024",
						References: []string{
							"https://github.com/btcsuite/go-socks/commit/233bccbb1abe02f05750f7ace66f5bffdb13defc",
						},
					},
				},
			},
		},
		{
			name:      "some files",
			ecosystem: "Go",
			dir:       filepath.Join("testdata", "somefiles"),
			wantValue: []want{
				{
					key: []string{"advisory-detail", "CVE-2020-8564", "Osv Security Advisories Go", "k8s.io/kubernetes/pkg/credentialprovider"},
					valueAdvisory: types.Advisory{
						VulnerableVersions: []string{">=0 <1.20.0-alpha.1"},
						PatchedVersions:    []string{"1.20.0-alpha.1"},
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2018-16886", "Osv Security Advisories Go", "go.etcd.io/etcd/auth"},
					valueAdvisory: types.Advisory{
						VulnerableVersions: []string{">=0 <0.5.0-alpha.5.0.20190108173120-83c051b701d3"},
						PatchedVersions:    []string{"0.5.0-alpha.5.0.20190108173120-83c051b701d3"},
					},
				},
			},
		},
		{
			name:    "sad path",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "failed to decode osv json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			tempDir := t.TempDir()

			err := db.Init(tempDir)
			require.NoError(t, err)
			defer db.Close()

			vulnSrc := NewVulnSrc(tt.ecosystem)
			err = vulnSrc.Update(tt.dir)

			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)

			db.Close()
			for _, wantValue := range tt.wantValue {
				switch wantValue.key[0] {
				case "advisory-detail":
					dbtest.JSONEq(t, db.Path(tempDir), wantValue.key, wantValue.valueAdvisory)
					continue
				case "vulnerability-detail":
					dbtest.JSONEq(t, db.Path(tempDir), wantValue.key, wantValue.valueVulnerability)
					continue
				}
			}

		})
	}
}

func TestGetVuln(t *testing.T) {
	type args struct {
		release string
		pkgName string
	}
	tests := []struct {
		name                       string
		args                       args
		ecosystem                  ecosystem
		forEachAdvisoryExpectation db.OperationForEachAdvisoryExpectation
		want                       []types.Advisory
		wantErr                    string
	}{
		{
			name:      "happy path PyPI",
			ecosystem: getEcoSystem(Python),
			args: args{
				release: "Osv Security Advisories PyPI",
				pkgName: "qutebrowser",
			},
			forEachAdvisoryExpectation: db.OperationForEachAdvisoryExpectation{
				Args: db.OperationForEachAdvisoryArgs{
					Source:  "Osv Security Advisories PyPI",
					PkgName: "qutebrowser",
				},
				Returns: db.OperationForEachAdvisoryReturns{
					Value: map[string][]byte{
						"CVE-2018-10895": []byte(`{"VulnerableVersions": ["\u003e=0 \u003c1.4.1"], "PatchedVersions": ["1.4.1"]}`),
					},
				},
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2018-10895",
					PatchedVersions:    []string{"1.4.1"},
					VulnerableVersions: []string{"\u003e=0 \u003c1.4.1"},
				},
			},
		},
		{
			name:      "happy path Go",
			ecosystem: getEcoSystem(Go),
			args: args{
				release: "Osv Security Advisories Go",
				pkgName: "math/big",
			},
			forEachAdvisoryExpectation: db.OperationForEachAdvisoryExpectation{
				Args: db.OperationForEachAdvisoryArgs{
					Source:  "Osv Security Advisories Go",
					PkgName: "math/big",
				},
				Returns: db.OperationForEachAdvisoryReturns{
					Value: map[string][]byte{
						"CVE-2020-28362": []byte(`{"VulnerableVersions": ["\u003e=1.14 \u003c1.14.12", "\u003e=1.15 \u003c1.15.5"], "PatchedVersions": ["1.14.12", "1.15.5"]}`),
					},
				},
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2020-28362",
					PatchedVersions:    []string{"1.14.12", "1.15.5"},
					VulnerableVersions: []string{"\u003e=1.14 \u003c1.14.12", "\u003e=1.15 \u003c1.15.5"},
				},
			},
		},
		{
			name:      "happy path crates.io",
			ecosystem: getEcoSystem(Rust),
			args: args{
				release: "Osv Security Advisories crates.io",
				pkgName: "multiqueue2",
			},
			forEachAdvisoryExpectation: db.OperationForEachAdvisoryExpectation{
				Args: db.OperationForEachAdvisoryArgs{
					Source:  "Osv Security Advisories crates.io",
					PkgName: "multiqueue2",
				},
				Returns: db.OperationForEachAdvisoryReturns{
					Value: map[string][]byte{
						"CVE-2020-36214": []byte(`{"VulnerableVersions": ["\u003e=0.0.0-0 \u003c0.1.7"], "PatchedVersions": ["0.1.7"]}`),
					},
				},
			},
			want: []types.Advisory{
				{
					VulnerabilityID:    "CVE-2020-36214",
					PatchedVersions:    []string{"0.1.7"},
					VulnerableVersions: []string{"\u003e=0.0.0-0 \u003c0.1.7"},
				},
			},
		},
		{
			name:      "GetAdvisories returns an error",
			ecosystem: getEcoSystem(Python),
			args: args{
				release: "qutebrowser",
				pkgName: "1.4.1",
			},
			forEachAdvisoryExpectation: db.OperationForEachAdvisoryExpectation{
				Args: db.OperationForEachAdvisoryArgs{
					Source:  "Osv Security Advisories PyPI",
					PkgName: "1.4.1",
				},
				Returns: db.OperationForEachAdvisoryReturns{
					Err: errors.New("error"),
				},
			},
			wantErr: "failed to iterate Osv",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockDBConfig := new(db.MockOperation)
			mockDBConfig.ApplyForEachAdvisoryExpectation(tt.forEachAdvisoryExpectation)

			vs := VulnSrc{
				dbc:       mockDBConfig,
				ecosystem: tt.ecosystem,
			}
			got, err := vs.Get(tt.args.pkgName)
			if tt.wantErr != "" {
				require.NotNil(t, err, tt.name)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
			} else {
				assert.NoError(t, err, tt.name)
			}
			assert.Equal(t, tt.want, got, tt.name)
		})
	}
}
