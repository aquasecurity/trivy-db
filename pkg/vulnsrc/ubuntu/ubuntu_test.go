package ubuntu_test

import (
	"errors"
	"testing"

	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/ubuntu"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
)

func TestVulnSrc_Update(t *testing.T) {
	tests := []struct {
		name       string
		dir        string
		opts       []ubuntu.Option
		wantValues []vulnsrctest.WantValues
		noBuckets  [][]string
		wantErr    string
	}{
		{
			name:    "invalid JSON",
			dir:     "testdata/invalid",
			wantErr: "json decode error",
		},
		{
			name: "write error stops iteration",
			dir:  "testdata",
			opts: []ubuntu.Option{
				ubuntu.WithCustomPut(func(db.Operation, *bolt.Tx, any) error {
					return errors.New("write failed")
				}),
			},
			wantErr: "write failed",
		},
		{
			name: "happy path",
			dir:  "testdata",
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"data-source", "ubuntu 18.04"},
					Value: types.DataSource{
						ID:   vulnerability.Ubuntu,
						Name: "Ubuntu CVE Tracker",
						URL:  "https://git.launchpad.net/ubuntu-cve-tracker",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2020-1234", "ubuntu 18.04", "xen"},
					Value: types.Advisory{
						FixedVersion: "1.2.3",
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2020-1234", "ubuntu"},
					Value: types.VulnerabilityDetail{
						Description: "Observable response discrepancy in some Intel(R) Processors may allow an authorized user to potentially enable information disclosure via local access.",
						Severity:    2,
						References:  []string{"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-0089"},
					},
				},
			},
			noBuckets: [][]string{
				{"advisory-detail", "CVE-2020-1234", "ubuntu 20.04"},
			},
		},
		{
			name: "pending status is included",
			dir:  "testdata",
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"data-source", "ubuntu 22.04"},
					Value: types.DataSource{
						ID:   vulnerability.Ubuntu,
						Name: "Ubuntu CVE Tracker",
						URL:  "https://git.launchpad.net/ubuntu-cve-tracker",
					},
				},
				{
					Key:   []string{"advisory-detail", "CVE-2020-1234", "ubuntu 22.04", "xen"},
					Value: types.Advisory{},
				},
			},
		},
		{
			name: "esm-infra-legacy release",
			dir:  "testdata",
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"data-source", "ubuntu 16.04-ESM"},
					Value: types.DataSource{
						ID:   vulnerability.Ubuntu,
						Name: "Ubuntu CVE Tracker",
						URL:  "https://git.launchpad.net/ubuntu-cve-tracker",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2026-109618", "ubuntu 16.04-ESM", "php7.0"},
					Value: types.Advisory{
						FixedVersion: "7.0.33-0ubuntu0.16.04.16+esm22",
					},
				},
				{
					Key: []string{"data-source", "ubuntu 14.04-ESM"},
					Value: types.DataSource{
						ID:   vulnerability.Ubuntu,
						Name: "Ubuntu CVE Tracker",
						URL:  "https://git.launchpad.net/ubuntu-cve-tracker",
					},
				},
				{
					Key: []string{"advisory-detail", "CVE-2026-109618", "ubuntu 14.04-ESM", "php5"},
					Value: types.Advisory{
						FixedVersion: "5.5.9+dfsg-1ubuntu4.29+esm18",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := ubuntu.NewVulnSrc(tt.opts...)
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
			})
		})
	}
}
