package redhatcsaf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/tools/txtar"

	"github.com/aquasecurity/trivy-db/pkg/utils"
)

// Each testdata/split/<parts>.txtar holds the files of a split document, which the test extracts into a directory before reading it.
// They were written by vuln-list-update from the documents in testdata/split/golden, except where noted.
func TestDecodeSplitDocument(t *testing.T) {
	tests := []struct {
		name  string
		parts string // the name of the txtar file with the parts, without the extension
		// patternDir extracts the parts into a directory whose name contains characters that are special in file name patterns.
		patternDir bool
		want       string // the golden file with the document the split one must be reassembled into
		wantErr    string
	}{
		{
			// The vendor branch is split by its child branches into 4 parts, and relationships into 2 parts.
			name:  "branches in 4 files",
			parts: "4-branches",
			want:  "advisory.json",
		},
		{
			// Assembled from vuln-list-update output: the parts of 4-branches, and the vulnerability parts written with a limit at which every product array is split.
			// product_status is split into one list per file, the single flag into 2 copies, the single score and threat into 4 copies each, and the remediations into halves.
			name:  "vulnerability arrays in several files",
			parts: "vulnerability-parts",
			want:  "advisory.json",
		},
		{
			// Hand-made from 4-branches: vuln-list-update does not split a single product_status list yet, but the format allows splitting it into several files with the same key.
			// Here known_not_affected is split into two files, and its lists must be appended rather than overwritten.
			name:  "product_status list in several files",
			parts: "product-status-same-key",
			want:  "advisory.json",
		},
		{
			// The vulnerabilities are numbered by their position in document.json, so the parts of the third one are vulnerabilities-0003-*, and the null one stays null.
			name:  "several vulnerabilities",
			parts: "several-vulnerabilities",
			want:  "several-vulnerabilities.json",
		},
		{
			// Hand-made from 4-branches: vuln-list-update puts a copy of a split entry in a part on its own, so entries next to a copy in the same part are never exercised by its output.
			// Here the first remediation is split across the first two parts, and the second one across the last two, so each merged copy is preceded or followed by another entry in the same part.
			name:  "entry copies next to other entries",
			parts: "entry-copies-with-siblings",
			want:  "advisory.json",
		},
		{
			// Hand-made from 4-branches: vuln-list-update moves branches out of document.json, but branches already in document.json must not be dropped when there are only relationship parts.
			name:  "branches in document.json",
			parts: "branches-in-document",
			want:  "advisory.json",
		},
		{
			// The vendor branch has a single product family branch, so both branches are copied into every part and merged back recursively.
			name:  "branch with a single child branch",
			parts: "single-child",
			want:  "single-child.json",
		},
		{
			// The first two parts hold the split x86_64 branch 4 levels deep, and the third part holds a product version right under the vendor branch.
			name:  "branches of different depth",
			parts: "different-depth",
			want:  "different-depth.json",
		},
		{
			// Hand-made: vuln-list-update puts a copy of a split branch in a part on its own, so the branches after the merged copy are never exercised by its output.
			// Here the copies of the Red Hat and x86_64 branches are followed by other branches on the same level, which must be appended rather than dropped.
			name:  "copy followed by other branches",
			parts: "copy-with-siblings",
			want:  "copy-with-siblings.json",
		},
		{
			// The part files are found by their names only, so they are read even if the path to them contains pattern characters.
			name:       "directory path with pattern characters",
			parts:      "4-branches",
			patternDir: true,
			want:       "advisory.json",
		},
		{
			// Hand-made: vuln-list-update keeps product_tree in document.json, but the parts must be read even without it.
			name:  "no product_tree in document.json",
			parts: "no-product-tree",
			want:  "advisory.json",
		},
		{
			// Hand-made: without branch parts, product_tree gets only relationships, and branches stay nil.
			name:  "only relationships",
			parts: "only-relationships",
			want:  "only-relationships.json",
		},
		{
			name:    "corrupt part",
			parts:   "corrupt-part",
			wantErr: "json decode error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), tt.parts)
			if tt.patternDir {
				dir = filepath.Join(t.TempDir(), "vuln-list[1]", tt.parts)
			}
			ar, err := txtar.ParseFile(filepath.Join("testdata", "split", tt.parts+".txtar"))
			require.NoError(t, err)
			fsys, err := txtar.FS(ar)
			require.NoError(t, err)
			require.NoError(t, os.CopyFS(dir, fsys))

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
