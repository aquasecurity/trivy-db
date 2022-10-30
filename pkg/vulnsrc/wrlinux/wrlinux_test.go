/*
 * Copyright (c) 2022 Wind River Systems, Inc.
 *
 * The right to copy, distribute, modify, or otherwise make use
 * of this software may be licensed only pursuant to the terms
 * of an applicable Wind River license agreement.
 */

package wrlinux_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/dbtest"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/wrlinux"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
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
					key: []string{"data-source", "WRLinux OS 10.19"},
					value: types.DataSource{
						ID:   vulnerability.WRLinux,
						Name: "WRLinux OS CVE metadata",
						URL:  "https://support2.windriver.com",
					},
				},
				{
					key: []string{"advisory-detail", "CVE-2020-24241", "WRLinux OS 10.19", "nasm"},
					value: types.Advisory{
						FixedVersion: "10.19.45.11",
					},
				},
				{
					key: []string{"vulnerability-detail", "CVE-2020-24241", "wrlinux"},
					value: types.VulnerabilityDetail{
						Description: "In Netwide Assembler (NASM) 2.15rc10, there is heap use-after-free in saa_wbytes in nasmlib/saa.c.",
						Severity:    2,
						References:  []string{},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cacheDir := dbtest.InitDB(t, nil)

			src := wrlinux.NewVulnSrc()
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
		})
	}
}
