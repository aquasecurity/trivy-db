package rapidfort

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
)

// TestResolveBucket pins which bucket a single range lands in. One feed file can
// mix distributions, so the range's identifier — not the version key it sits
// under — decides, and the feed's own OS supplies whatever the identifier leaves
// unsaid. These bucket names are the keys Trivy queries at scan time, so a
// change here silently stops matching.
func TestResolveBucket(t *testing.T) {
	tests := []struct {
		name     string
		eco      ecosystem.Type
		ecoVer   string
		event    Event
		wantName string
		wantErr  string
	}{
		// "elN" is the whole Enterprise Linux family's dist tag, so it names the
		// release only: the distribution still comes from the feed that shipped it.
		{
			name:     "el9 on the redhat feed",
			eco:      ecosystem.RedHat,
			ecoVer:   "9",
			event:    Event{Identifier: "el9", Fixed: "7.76.1-26.el9_3.3"},
			wantName: "rapidfort Red Hat 9",
		},
		{
			name:     "el9 on the oracle feed",
			eco:      ecosystem.OracleLinux,
			ecoVer:   "9",
			event:    Event{Identifier: "el9", Fixed: "7.76.1-26.el9_3.3"},
			wantName: "rapidfort Oracle Linux 9",
		},
		{
			name:     "el8 on the rocky feed",
			eco:      ecosystem.Rocky,
			ecoVer:   "8",
			event:    Event{Identifier: "el8", Fixed: "7.61.1-30.el8"},
			wantName: "rapidfort rocky 8",
		},
		{
			name:     "el9 on the alma feed",
			eco:      ecosystem.AlmaLinux,
			ecoVer:   "9",
			event:    Event{Identifier: "el9", Fixed: "7.76.1-26.el9"},
			wantName: "rapidfort alma 9",
		},
		// The identifier overrides the version key: an el8 range listed under
		// the "9" key belongs to the 8 bucket.
		{
			name:     "el8 range listed under the 9 key",
			eco:      ecosystem.RedHat,
			ecoVer:   "9",
			event:    Event{Identifier: "el8", Fixed: "7.61.1-30.el8"},
			wantName: "rapidfort Red Hat 8",
		},
		// Amazon Linux tags releases "amznN" rather than "elN".
		{
			name:     "amzn2023 on the amazon feed",
			eco:      ecosystem.AmazonLinux,
			ecoVer:   "2023",
			event:    Event{Identifier: "amzn2023", Fixed: "8.5.0-1.amzn2023"},
			wantName: "rapidfort amazon linux 2023",
		},
		{
			name:     "amzn2 on the amazon feed",
			eco:      ecosystem.AmazonLinux,
			ecoVer:   "2",
			event:    Event{Identifier: "amzn2", Fixed: "8.5.0-1.amzn2"},
			wantName: "rapidfort amazon linux 2",
		},
		// "fcNN" names Fedora itself, so it overrides the feed's OS as well.
		// Every RPM feed carries these, and mergeEntries unions the copies.
		{
			name:     "fc43 on the redhat feed",
			eco:      ecosystem.RedHat,
			ecoVer:   "9",
			event:    Event{Identifier: "fc43", Fixed: "8.11.1-1.fc43"},
			wantName: "rapidfort fedora 43",
		},
		{
			name:     "fc43 on the oracle feed",
			eco:      ecosystem.OracleLinux,
			ecoVer:   "9",
			event:    Event{Identifier: "fc43", Fixed: "8.11.1-1.fc43"},
			wantName: "rapidfort fedora 43",
		},
		// A rebuild keeps the feed's OS and drops the release.
		{
			name:     "rf on the redhat feed",
			eco:      ecosystem.RedHat,
			ecoVer:   "9",
			event:    Event{Identifier: "rf", Fixed: "7.76.1-26.rf1"},
			wantName: "rapidfort Red Hat",
		},
		{
			name:     "rf on the oracle feed",
			eco:      ecosystem.OracleLinux,
			ecoVer:   "9",
			event:    Event{Identifier: "rf", Fixed: "7.76.1-26.rf1"},
			wantName: "rapidfort Oracle Linux",
		},
		{
			name:     "rf on the amazon feed",
			eco:      ecosystem.AmazonLinux,
			ecoVer:   "2023",
			event:    Event{Identifier: "rf", Fixed: "8.5.0-1.rf1"},
			wantName: "rapidfort amazon linux",
		},
		{
			name:     "rf on the ubuntu feed",
			eco:      ecosystem.Ubuntu,
			ecoVer:   "22.04",
			event:    Event{Identifier: "rf", Fixed: "0:2.46-10rfubu"},
			wantName: "rapidfort ubuntu",
		},
		{
			name:     "rf on the debian feed",
			eco:      ecosystem.Debian,
			ecoVer:   "12",
			event:    Event{Identifier: "rf", Fixed: "0:2.48.2-0rfubu"},
			wantName: "rapidfort debian",
		},
		// A feed names its own distribution's packages by ecosystem name.
		{
			name:     "ubuntu identifier on the ubuntu feed",
			eco:      ecosystem.Ubuntu,
			ecoVer:   "22.04",
			event:    Event{Identifier: "ubuntu", Fixed: "0:2.46-1ubuntu1"},
			wantName: "rapidfort ubuntu 22.04",
		},
		{
			name:     "debian identifier on the debian feed",
			eco:      ecosystem.Debian,
			ecoVer:   "12",
			event:    Event{Identifier: "debian", Fixed: "1:2.39.5-3"},
			wantName: "rapidfort debian 12",
		},
		// An explicit identifier is authoritative: the annotated part of the
		// Ubuntu feed must not be second-guessed by the marker heuristic.
		{
			name:     "explicit distro identifier beats an rf marker",
			eco:      ecosystem.Ubuntu,
			ecoVer:   "22.04",
			event:    Event{Identifier: "ubuntu", Fixed: "0:2.46-10rfubu"},
			wantName: "rapidfort ubuntu 22.04",
		},
		{
			name:     "explicit rf identifier without a marker still splits out",
			eco:      ecosystem.Ubuntu,
			ecoVer:   "22.04",
			event:    Event{Identifier: "rf", Fixed: "0:2.46-10"},
			wantName: "rapidfort ubuntu",
		},
		{
			name:     "unannotated distro fix stays on the base OS",
			eco:      ecosystem.Debian,
			ecoVer:   "13",
			event:    Event{Introduced: "0:0", Fixed: "1:2.39.5-3"},
			wantName: "rapidfort debian 13",
		},
		{
			name:     "unannotated distro fix on the ubuntu feed stays on the base OS",
			eco:      ecosystem.Ubuntu,
			ecoVer:   "20.04",
			event:    Event{Fixed: "7.81.0-1ubuntu1.15"},
			wantName: "rapidfort ubuntu 20.04",
		},
		// Alpine annotates nothing and ships no rebuilds, so its ranges belong
		// to the release the file lists them under.
		{
			name:     "untagged alpine range",
			eco:      ecosystem.Alpine,
			ecoVer:   "3.18",
			event:    Event{Fixed: "8.11.1-r0"},
			wantName: "rapidfort alpine 3.18",
		},

		// Anything that can't be attributed is dropped rather than guessed, so
		// the caller logs and skips the range instead of inventing a platform.
		{
			name:    "el with no release",
			eco:     ecosystem.RedHat,
			ecoVer:  "9",
			event:   Event{Identifier: "el", Fixed: "7.76.1-26"},
			wantErr: "unusable distribution version",
		},
		{
			name:    "non-numeric el release",
			eco:     ecosystem.RedHat,
			ecoVer:  "9",
			event:   Event{Identifier: "el9beta", Fixed: "7.76.1-26"},
			wantErr: "unusable distribution version",
		},
		{
			name:    "non-numeric amzn release",
			eco:     ecosystem.AmazonLinux,
			ecoVer:  "2023",
			event:   Event{Identifier: "amznX", Fixed: "8.5.0-1"},
			wantErr: "unusable distribution version",
		},
		{
			name:    "fc with no release",
			eco:     ecosystem.RedHat,
			ecoVer:  "9",
			event:   Event{Identifier: "fcrawhide", Fixed: "8.11.1-1"},
			wantErr: "unusable distribution version",
		},
		// An empty version key must not fold a distribution range into the
		// release-less rebuild bucket.
		{
			name:    "untagged range under an empty version key",
			eco:     ecosystem.Ubuntu,
			ecoVer:  "",
			event:   Event{Fixed: "7.81.0-1ubuntu1.15"},
			wantErr: "unusable distribution version",
		},
		// A feed must not claim another distribution's ranges: the buckets are
		// keyed by version, and "12" means nothing on the Ubuntu side.
		{
			name:    "debian identifier on the ubuntu feed",
			eco:     ecosystem.Ubuntu,
			ecoVer:  "22.04",
			event:   Event{Identifier: "debian", Fixed: "1:2.39.5-3"},
			wantErr: "unusable distribution identifier",
		},
		{
			name:    "ubuntu identifier on the debian feed",
			eco:     ecosystem.Debian,
			ecoVer:  "12",
			event:   Event{Identifier: "ubuntu", Fixed: "0:2.46-1ubuntu1"},
			wantErr: "unusable distribution identifier",
		},
		{
			name:    "unknown distribution prefix",
			eco:     ecosystem.RedHat,
			ecoVer:  "9",
			event:   Event{Identifier: "sles15", Fixed: "7.76.1-26"},
			wantErr: "unusable distribution identifier",
		},
		// A rebuild on a feed this build does not ingest has no bucket to go to.
		{
			name:    "rf on an unsupported feed",
			eco:     ecosystem.PhotonOS,
			ecoVer:  "5.0",
			event:   Event{Identifier: "rf", Fixed: "8.11.1-1.rf"},
			wantErr: "unsupported base ecosystem",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveBucket(tt.eco, tt.ecoVer, tt.event.Identifier)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantName, got.Name())
		})
	}
}
