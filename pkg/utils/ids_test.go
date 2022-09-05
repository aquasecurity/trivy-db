package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetUniqueIDsFromReferences(t *testing.T) {
	tests := []struct {
		title      string
		known      []string
		references []string
		ids        []string
	}{
		{
			title: "happy path",
			known: []string{},
			references: []string{
				"https://github.com/Sylius/Sylius/security/advisories/GHSA-4qrp-27r3-66fj",
				"https://github.com/Sylius/Sylius/releases/tag/v1.10.11",
				"https://github.com/Sylius/Sylius/releases/tag/v1.11.2",
				"https://github.com/Sylius/Sylius/releases/tag/v1.9.10",
				"https://nvd.nist.gov/vuln/detail/CVE-2022-24749",
				"https://github.com/advisories/GHSA-4qrp-27r3-66fj",
			},
			ids: []string{
				"CVE-2022-24749",
				"GHSA-4qrp-27r3-66fj",
			},
		},
		{
			title: "there is a known ID",
			known: []string{
				"GHSA-4qrp-27r3-66fj",
			},
			references: []string{
				"https://github.com/Sylius/Sylius/security/advisories/GHSA-4qrp-27r3-66fj",
				"https://github.com/Sylius/Sylius/releases/tag/v1.10.11",
				"https://github.com/Sylius/Sylius/releases/tag/v1.11.2",
				"https://github.com/Sylius/Sylius/releases/tag/v1.9.10",
				"https://nvd.nist.gov/vuln/detail/CVE-2022-24749",
				"https://github.com/advisories/GHSA-4qrp-27r3-66fj",
			},
			ids: []string{
				"CVE-2022-24749",
			},
		},
		{
			title: "no references, but there is a known vuln",
			known: []string{
				"GHSA-4qrp-27r3-66fj",
			},
			references: []string{},
			ids:        []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.title, func(t *testing.T) {
			got := GetUniqueIDsFromReferences(tt.references, tt.known)
			assert.Equal(t, tt.ids, got)
		})
	}
}
