package redhatcsaf

import (
	"path/filepath"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/samber/lo"
	"github.com/samber/oops"

	"github.com/aquasecurity/trivy-db/pkg/utils"
)

// vuln-list-redhat stores a document too large for GitHub as the <cve-id>/ directory instead of <cve-id>.json:
//   - document.json holds the document without product_tree.branches and product_tree.relationships;
//   - branches-NNNN.json hold parts of product_tree.branches;
//   - relationships-NNNN.json hold parts of product_tree.relationships.
//
// A branch that does not fit in one file is split by its child branches, and each part is wrapped in a copy of the branch.
// cf. https://github.com/aquasecurity/vuln-list-update/pull/495
const (
	splitDocumentFile         = "document.json"
	splitBranchesPattern      = "branches-*.json"
	splitRelationshipsPattern = "relationships-*.json"
)

// isSplitDocument reports whether dir holds a split CSAF VEX document.
func isSplitDocument(dir string) (bool, error) {
	return utils.Exists(filepath.Join(dir, splitDocumentFile))
}

// decodeSplitDocument reassembles a CSAF VEX document split into the dir directory.
// The parts are read in the order of their numbers, and the branch parts are merged back by mergeBranches.
func decodeSplitDocument(dir string) (csaf.Advisory, error) {
	eb := oops.With("dir", dir)

	var adv csaf.Advisory
	if err := utils.UnmarshalJSONFile(&adv, filepath.Join(dir, splitDocumentFile)); err != nil {
		return csaf.Advisory{}, eb.Wrap(err)
	}

	// The part numbers are zero-padded, so the lexical order of the names is the order of the parts.
	branchFiles, err := filepath.Glob(filepath.Join(dir, splitBranchesPattern))
	if err != nil {
		return csaf.Advisory{}, eb.Wrapf(err, "glob error")
	}
	var branches csaf.Branches
	for _, f := range branchFiles {
		var part csaf.Branches
		if err := utils.UnmarshalJSONFile(&part, f); err != nil {
			return csaf.Advisory{}, eb.Wrap(err)
		}
		branches = mergeBranches(branches, part)
	}

	relationshipFiles, err := filepath.Glob(filepath.Join(dir, splitRelationshipsPattern))
	if err != nil {
		return csaf.Advisory{}, eb.Wrapf(err, "glob error")
	}
	var relationships csaf.Relationships
	for _, f := range relationshipFiles {
		var part csaf.Relationships
		if err := utils.UnmarshalJSONFile(&part, f); err != nil {
			return csaf.Advisory{}, eb.Wrap(err)
		}
		// Relationships are a flat list, and a single relationship is never split, so unlike branches, the parts are simply concatenated.
		relationships = append(relationships, part...)
	}

	if len(branches) > 0 || len(relationships) > 0 {
		if adv.ProductTree == nil {
			adv.ProductTree = &csaf.ProductTree{}
		}
		adv.ProductTree.Branches = branches
		if len(relationships) > 0 {
			adv.ProductTree.RelationShips = &relationships
		}
	}
	return adv, nil
}

// mergeBranches appends the branches of the next part to the branches read so far.
// When a branch is split, its parts are wrapped in copies of the branch, so the last branch read so far and the first branch of the next part are copies of the same branch.
// They are merged into one, recursively, since a branch with a single child branch wraps the parts of that child as well.
// Only this boundary is merged: branches within one part are never copies of each other.
func mergeBranches(dst, src csaf.Branches) csaf.Branches {
	if len(dst) == 0 || len(src) == 0 || !sameBranch(dst[len(dst)-1], src[0]) {
		return append(dst, src...)
	}
	merged := *dst[len(dst)-1]
	merged.Branches = mergeBranches(append(csaf.Branches(nil), merged.Branches...), src[0].Branches)
	dst[len(dst)-1] = &merged
	return append(dst, src[1:]...)
}

// sameBranch reports whether a and b are copies of the same split branch.
// A split branch always has child branches, which tells it apart from leaf branches with the same name.
func sameBranch(a, b *csaf.Branch) bool {
	return a != nil && b != nil && len(a.Branches) > 0 && len(b.Branches) > 0 &&
		lo.FromPtr(a.Category) == lo.FromPtr(b.Category) && lo.FromPtr(a.Name) == lo.FromPtr(b.Name)
}
