package redhatcsaf

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/samber/lo"
	"github.com/samber/oops"

	"github.com/aquasecurity/trivy-db/pkg/utils"
)

// vuln-list-redhat stores a document too large for GitHub as the <cve-id>/ directory instead of <cve-id>.json:
//   - document.json holds the document without product_tree.branches, product_tree.relationships and the product arrays of the vulnerabilities;
//   - branches-NNNN.json hold parts of product_tree.branches;
//   - relationships-NNNN.json hold parts of product_tree.relationships;
//   - vulnerabilities-NNNN-<field>-NNNN.json hold parts of product_status, scores, threats, flags and remediations of each vulnerability (see decodeVulnerabilityParts).
//
// A branch that does not fit in one file is split by its child branches, and each part is wrapped in a copy of the branch.
// Likewise, an entry of scores, threats, flags or remediations that does not fit in one file is split into copies holding parts of its product list.
// cf. https://github.com/aquasecurity/vuln-list-update/pull/495
const (
	splitDocumentFile         = "document.json"
	splitBranchesPattern      = "branches-*.json"
	splitRelationshipsPattern = "relationships-*.json"

	// splitVulnerabilityPrefix is the prefix of the part files of a vulnerability, formatted with its number in document.json, starting from 1.
	// The patterns below are appended to it.
	splitVulnerabilityPrefix  = "vulnerabilities-%04d-"
	splitProductStatusPattern = "product_status-*.json"
	splitScoresPattern        = "scores-*.json"
	splitThreatsPattern       = "threats-*.json"
	splitFlagsPattern         = "flags-*.json"
	splitRemediationsPattern  = "remediations-*.json"
)

// isSplitDocument reports whether dir holds a split CSAF VEX document.
func isSplitDocument(dir string) (bool, error) {
	return utils.Exists(filepath.Join(dir, splitDocumentFile))
}

// decodeSplitDocument reassembles a CSAF VEX document split into the dir directory.
// The parts are read in the order of their numbers, the branch parts are merged back by mergeBranches, and the vulnerability parts by decodeVulnerabilityParts.
func decodeSplitDocument(dir string) (csaf.Advisory, error) {
	eb := oops.With("dir", dir)

	var adv csaf.Advisory
	if err := utils.UnmarshalJSONFile(&adv, filepath.Join(dir, splitDocumentFile)); err != nil {
		return csaf.Advisory{}, eb.Wrap(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return csaf.Advisory{}, eb.Wrapf(err, "read dir error")
	}

	branchFiles, err := partFiles(dir, entries, splitBranchesPattern)
	if err != nil {
		return csaf.Advisory{}, eb.Wrap(err)
	}
	var branches csaf.Branches
	for _, f := range branchFiles {
		var part csaf.Branches
		if err := utils.UnmarshalJSONFile(&part, f); err != nil {
			return csaf.Advisory{}, eb.Wrap(err)
		}
		branches = mergeBranches(branches, part)
	}

	relationshipFiles, err := partFiles(dir, entries, splitRelationshipsPattern)
	if err != nil {
		return csaf.Advisory{}, eb.Wrap(err)
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
		// vuln-list-update moves both lists out of document.json, but a list without parts is kept as it is in document.json rather than dropped.
		if len(branches) > 0 {
			adv.ProductTree.Branches = branches
		}
		if len(relationships) > 0 {
			adv.ProductTree.RelationShips = &relationships
		}
	}

	if err := decodeVulnerabilityParts(dir, entries, &adv); err != nil {
		return csaf.Advisory{}, eb.Wrap(err)
	}
	return adv, nil
}

// decodeVulnerabilityParts reads the product arrays of each vulnerability of adv back from their part files:
//   - vulnerabilities-NNNN-product_status-NNNN.json hold product_status objects, each holding some of its lists, and the lists are appended in order;
//   - vulnerabilities-NNNN-scores-NNNN.json, -threats-, -flags- and -remediations- hold parts of these arrays, which are concatenated in order, and copies of a split entry are merged back by mergeByProducts.
//
// The file names start with splitVulnerabilityPrefix, which holds the number of the vulnerability.
func decodeVulnerabilityParts(dir string, entries []os.DirEntry, adv *csaf.Advisory) error {
	for i, v := range adv.Vulnerabilities {
		if v == nil {
			continue
		}
		prefix := fmt.Sprintf(splitVulnerabilityPrefix, i+1)

		statusFiles, err := partFiles(dir, entries, prefix+splitProductStatusPattern)
		if err != nil {
			return err
		}
		for _, f := range statusFiles {
			var part csaf.ProductStatus
			if err := utils.UnmarshalJSONFile(&part, f); err != nil {
				return err
			}
			if v.ProductStatus == nil {
				v.ProductStatus = &csaf.ProductStatus{}
			}
			for _, list := range productStatusLists {
				appendProducts(list(v.ProductStatus), *list(&part))
			}
		}

		files := func(pattern string) ([]string, error) {
			return partFiles(dir, entries, prefix+pattern)
		}
		decoders := []func() error{
			func() error {
				return decodeEntryParts(files, splitScoresPattern, &v.Scores, func(s *csaf.Score) **csaf.Products { return &s.Products })
			},
			func() error {
				return decodeEntryParts(files, splitThreatsPattern, &v.Threats, func(t *csaf.Threat) **csaf.Products { return &t.ProductIds })
			},
			func() error {
				return decodeEntryParts(files, splitFlagsPattern, &v.Flags, func(f *csaf.Flag) **csaf.Products { return &f.ProductIds })
			},
			func() error {
				return decodeEntryParts(files, splitRemediationsPattern, &v.Remediations, func(r *csaf.Remediation) **csaf.Products { return &r.ProductIds })
			},
		}
		for _, decode := range decoders {
			if err := decode(); err != nil {
				return err
			}
		}
	}
	return nil
}

// productStatusLists are accessors to the fields of all lists of product_status.
var productStatusLists = []func(*csaf.ProductStatus) **csaf.Products{
	func(s *csaf.ProductStatus) **csaf.Products { return &s.FirstAffected },
	func(s *csaf.ProductStatus) **csaf.Products { return &s.FirstFixed },
	func(s *csaf.ProductStatus) **csaf.Products { return &s.Fixed },
	func(s *csaf.ProductStatus) **csaf.Products { return &s.KnownAffected },
	func(s *csaf.ProductStatus) **csaf.Products { return &s.KnownNotAffected },
	func(s *csaf.ProductStatus) **csaf.Products { return &s.LastAffected },
	func(s *csaf.ProductStatus) **csaf.Products { return &s.Recommended },
	func(s *csaf.ProductStatus) **csaf.Products { return &s.UnderInvestigation },
}

// appendProducts appends the product IDs of src to the list in dst, creating the list if needed.
// A nil src leaves dst unchanged, so a list missing from every part stays nil.
func appendProducts(dst **csaf.Products, src *csaf.Products) {
	if src == nil {
		return
	}
	if *dst == nil {
		*dst = &csaf.Products{}
	}
	**dst = append(**dst, *src...)
}

// decodeEntryParts reads the part files of an array of scores, threats, flags or remediations matching pattern, in order, and appends them to the array in dst by mergeByProducts.
// files returns the part files of the vulnerability matching a pattern, and products returns the product list field of an entry.
func decodeEntryParts[S ~[]*E, E any](files func(pattern string) ([]string, error), pattern string, dst *S, products func(*E) **csaf.Products) error {
	paths, err := files(pattern)
	if err != nil {
		return err
	}
	for _, path := range paths {
		var part S
		if err := utils.UnmarshalJSONFile(&part, path); err != nil {
			return err
		}
		*dst = mergeByProducts(*dst, part, products)
	}
	return nil
}

// mergeByProducts appends the entries of the next part to the entries read so far.
// When an entry is too large for one file, it is split into copies holding parts of its product list, so the last entry read so far and the first entry of the next part may be copies of the same entry.
// They are merged into one by concatenating their product lists if everything else in them is equal.
// Only this boundary is merged: entries within one part are never copies of each other.
// Two different adjacent entries that differ only in their product lists are merged as well if they meet at a boundary, which does not change their meaning.
// The entries read so far are owned by the decoder, so the product list of the last one is extended in place.
func mergeByProducts[S ~[]*E, E any](dst, src S, products func(*E) **csaf.Products) S {
	if len(dst) == 0 || len(src) == 0 || !sameExceptProducts(dst[len(dst)-1], src[0], products) {
		return append(dst, src...)
	}
	appendProducts(products(dst[len(dst)-1]), *products(src[0]))
	return append(dst, src[1:]...)
}

// sameExceptProducts reports whether a and b are copies of the same split entry: both have products, and everything else in them is equal.
func sameExceptProducts[E any](a, b *E, products func(*E) **csaf.Products) bool {
	if a == nil || b == nil || len(lo.FromPtr(*products(a))) == 0 || len(lo.FromPtr(*products(b))) == 0 {
		return false
	}
	ac, bc := *a, *b
	*products(&ac) = nil
	*products(&bc) = nil
	return reflect.DeepEqual(ac, bc)
}

// partFiles returns the paths of the part files in dir whose names match pattern, in the order of the parts.
// Only the names are matched, since dir itself may contain characters that are special in patterns.
// os.ReadDir sorts the entries by name, and the part numbers are zero-padded, so the order of the names is the order of the parts.
func partFiles(dir string, entries []os.DirEntry, pattern string) ([]string, error) {
	var paths []string
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		ok, err := filepath.Match(pattern, e.Name())
		if err != nil {
			return nil, oops.With("pattern", pattern).Wrapf(err, "pattern error")
		} else if ok {
			paths = append(paths, filepath.Join(dir, e.Name()))
		}
	}
	return paths, nil
}

// mergeBranches appends the branches of the next part to the branches read so far.
// When a branch is split, its parts are wrapped in copies of the branch, so the last branch read so far and the first branch of the next part are copies of the same branch.
// They are merged into one, recursively, since a branch with a single child branch wraps the parts of that child as well.
// Only this boundary is merged: branches within one part are never copies of each other.
// Two different adjacent branches with the same category and name that both have child branches are merged as well if they meet at a boundary.
// The parser looks products up by product ID across all branches, so this does not change the result.
// The branches read so far are owned by the decoder, so the last one is extended in place.
func mergeBranches(dst, src csaf.Branches) csaf.Branches {
	if len(dst) == 0 || len(src) == 0 || !sameBranch(dst[len(dst)-1], src[0]) {
		return append(dst, src...)
	}
	last := dst[len(dst)-1]
	last.Branches = mergeBranches(last.Branches, src[0].Branches)
	return append(dst, src[1:]...)
}

// sameBranch reports whether a and b are copies of the same split branch.
// A split branch always has child branches, which tells it apart from leaf branches with the same name.
func sameBranch(a, b *csaf.Branch) bool {
	return a != nil && b != nil && len(a.Branches) > 0 && len(b.Branches) > 0 &&
		lo.FromPtr(a.Category) == lo.FromPtr(b.Category) && lo.FromPtr(a.Name) == lo.FromPtr(b.Name)
}
