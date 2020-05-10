package bundler

import (
	"os"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

func Test_walkFunc(t *testing.T) {
	mockDBConfig := new(db.MockOperation)
	mockDBConfig.ApplyPutAdvisoryExpectations([]db.PutAdvisoryExpectation{
		{
			Args: db.PutAdvisoryArgs{
				TxAnything:      true,
				Source:          vulnerability.RubySec,
				PkgName:         "doorkeeper-openid_connect",
				VulnerabilityID: "CVE-2019-9837",
				Advisory: Advisory{
					//VulnerabilityID:    "CVE-2018-16487", // TODO: Why is this field needed if the key is already the same?
					PatchedVersions:    []string{">= 1.5.4"},
					UnaffectedVersions: []string{"< 1.4.0"},
				},
			},
		},
	})
	mockDBConfig.ApplyPutVulnerabilityDetailExpectations([]db.PutVulnerabilityDetailExpectation{
		{
			Args: db.PutVulnerabilityDetailArgs{
				TxAnything:      true,
				VulnerabilityID: "CVE-2019-9837",
				Source:          vulnerability.RubySec,
				Vulnerability: types.VulnerabilityDetail{
					ID:          "CVE-2019-9837", // TODO: Why is this field needed if the key is already the same?
					CvssScore:   0,
					CvssScoreV3: 6.1,
					References:  []string{"https://github.com/doorkeeper-gem/doorkeeper-openid_connect/blob/master/CHANGELOG.md#v154-2019-02-15"},
					Title:       "Doorkeeper::OpenidConnect Open Redirect",
					Description: "Doorkeeper::OpenidConnect (aka the OpenID Connect extension for Doorkeeper) 1.4.x and 1.5.x before 1.5.4 has an open redirect via the redirect_uri field in an OAuth authorization request (that results in an error response) with the 'openid' scope and a prompt=none value. This allows phishing attacks against the authorization flow.",
				},
			},
		},
	})
	mockDBConfig.ApplyPutSeverityExpectations([]db.PutSeverityExpectation{
		{
			Args: db.PutSeverityArgs{
				TxAnything:      true,
				VulnerabilityID: "CVE-2019-9837",
				Severity:        0,
			},
		},
	})

	vs := VulnSrc{dbc: mockDBConfig}

	filePath := "testdata/CVE-2019-9837.yml"
	fi, err := os.Lstat(filePath)
	require.NoError(t, err)

	require.NoError(t, vs.walkFunc(err, fi, filePath, &bolt.Tx{}))
}
