package ubuntu_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/ubuntu"
)

func TestVulnSrc_Update(t *testing.T) {
	type wantKV struct {
		key   []string
		value interface{}
	}
	tests := []struct {
		name       string
		statuses   []string
		wantValues []wantKV
		noBuckets  [][]string
		wantErr    string
	}{
		{
			name: "happy path",
			wantValues: []wantKV{
				{
					key: []string{"advisory-detail", "CVE-2020-1234", "ubuntu 18.04", "xen"},
					value: types.Advisory{
						FixedVersion: "1.2.3",
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2020-1234", "ubuntu"},
					value: types.VulnerabilityDetail{
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
			name:     "custom statuses",
			statuses: []string{"released", "needs-triage"},
			wantValues: []wantKV{
				{
					key: []string{"advisory-detail", "CVE-2020-1234", "ubuntu 18.04", "xen"},
					value: types.Advisory{
						FixedVersion: "1.2.3",
					},
				},
				{
					key:   []string{"advisory-detail", "CVE-2020-1234", "ubuntu 20.04", "xen"},
					value: types.Advisory{},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2020-1234", "ubuntu"},
					value: types.VulnerabilityDetail{
						Description: "Observable response discrepancy in some Intel(R) Processors may allow an authorized user to potentially enable information disclosure via local access.",
						Severity:    2,
						References:  []string{"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-0089"},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cacheDir := dbtest.InitTestDB(t, nil)

			var options []ubuntu.Option
			if len(tt.statuses) != 0 {
				options = append(options, ubuntu.WithStatuses(tt.statuses))
			}
			src := ubuntu.NewVulnSrc(options...)
			err := src.Update("testdata")
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			}

			require.NoError(t, err, tt.name)

			// Compare DB entries
			require.NoError(t, err, db.Close())
			dbPath := db.Path(cacheDir)
			for _, want := range tt.wantValues {
				dbtest.JSONEq(t, dbPath, want.key, want.value)
			}

			// Verify these buckets don't exist
			for _, noBuckets := range tt.noBuckets {
				dbtest.NoBucket(t, dbPath, noBuckets, "the bucket exists")
			}
		})
	}
}
