package alpine

import (
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
	"path/filepath"
	"testing"
	"time"
)

func TestEolSrc_Update(t *testing.T) {
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
					Key: []string{"eol", "alpine"},
					Value: map[string]time.Time{
						"3.14": time.Date(2023, 5, 1, 23, 59, 59, 0, time.UTC),
						"3.15": time.Date(2023, 11, 1, 23, 59, 59, 0, time.UTC),
						"edge": time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC),
					},
				},
			},
		},
		{
			name:    "sad path",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "failed to decode list of end-of-life dates",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			es := NewEolSrc()
			vulnsrctest.TestUpdate(t, es, vulnsrctest.TestUpdateArgs{
				Dir:        test.dir,
				WantValues: test.wantValues,
				WantErr:    test.wantErr,
			})
		})
	}
}
