package ubuntu

import "testing"

func TestUbuntuReleasesMapping_compoundKeys(t *testing.T) {
	tests := []struct {
		release string
		want    string
	}{
		{"fips-updates/jammy", "22.04"},
		{"fips-preview/jammy", "22.04"},
		{"fips/bionic", "18.04"},
		{"fips-updates/bionic", "18.04"},
		{"fips-updates/focal", "20.04"},
		{"fips-updates/noble", "24.04"},
		{"fips/xenial", "16.04"},
		{"esm-apps/jammy", "22.04-ESM"},
		{"esm-apps/noble", "24.04-ESM"},
		{"esm-apps/resolute", "26.04-ESM"},
		{"esm-infra/jammy", "22.04-ESM"},
		{"esm-infra/noble", "24.04-ESM"},
		{"esm-infra/resolute", "26.04-ESM"},
		{"esm-infra-legacy/trusty", "14.04-ESM"},
		{"esm-infra/focal", "20.04-ESM"},
		{"esm-apps/focal", "20.04-ESM"},
		{"trusty/esm", "14.04-ESM"},
		{"jammy", "22.04"},
	}
	for _, tt := range tests {
		t.Run(tt.release, func(t *testing.T) {
			got, ok := UbuntuReleasesMapping[tt.release]
			if !ok {
				t.Fatalf("missing key %q in UbuntuReleasesMapping", tt.release)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
