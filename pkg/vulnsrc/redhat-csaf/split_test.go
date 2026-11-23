package redhatcsaf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/utils"
)

// The split documents in testdata/split were written by vuln-list-update from the documents in testdata/split/golden, except where noted.
func TestDecodeSplitDocument(t *testing.T) {
	tests := []struct {
		name string
		dir  string
		// patternDir copies dir into a directory whose name contains characters that are special in file name patterns.
		patternDir bool
		want       string // the golden file with the document the split one must be reassembled into
		wantErr    string
	}{
		{
			// The vendor branch is split by its child branches into 4 parts, and relationships into 2 parts.
			name: "branches in 4 files",
			dir:  "4-branches",
			want: "advisory.json",
		},
		{
			// The vendor branch has a single product family branch, so both branches are copied into every part and merged back recursively.
			name: "branch with a single child branch",
			dir:  "single-child",
			want: "single-child.json",
		},
		{
			// The first two parts hold the split x86_64 branch 4 levels deep, and the third part holds a product version right under the vendor branch.
			name: "branches of different depth",
			dir:  "different-depth",
			want: "different-depth.json",
		},
		{
			// Hand-made: vuln-list-update puts a copy of a split branch in a part on its own, so the branches after the merged copy are never exercised by its output.
			// Here the copies of the Red Hat and x86_64 branches are followed by other branches on the same level, which must be appended rather than dropped.
			name: "copy followed by other branches",
			dir:  "copy-with-siblings",
			want: "copy-with-siblings.json",
		},
		{
			// The part files are found by their names only, so they are read even if the path to them contains pattern characters.
			name:       "directory path with pattern characters",
			dir:        "4-branches",
			patternDir: true,
			want:       "advisory.json",
		},
		{
			// Hand-made: vuln-list-update keeps product_tree in document.json, but the parts must be read even without it.
			name: "no product_tree in document.json",
			dir:  "no-product-tree",
			want: "advisory.json",
		},
		{
			// Hand-made: without branch parts, product_tree gets only relationships, and branches stay nil.
			name: "only relationships",
			dir:  "only-relationships",
			want: "only-relationships.json",
		},
		{
			name:    "corrupt part",
			dir:     "corrupt-part",
			wantErr: "json decode error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := filepath.Join("testdata", "split", tt.dir)
			if tt.patternDir {
				patternDir := filepath.Join(t.TempDir(), "vuln-list[1]", tt.dir)
				require.NoError(t, os.CopyFS(patternDir, os.DirFS(dir)))
				dir = patternDir
			}
			got, err := decodeSplitDocument(dir)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			var want csaf.Advisory
			require.NoError(t, utils.UnmarshalJSONFile(&want, filepath.Join("testdata", "split", "golden", tt.want)))
			assert.Equal(t, want, got)
		})
	}
}
