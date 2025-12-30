package redhatcsaf

import (
	"fmt"
	"strings"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
)

// CSAFAdvisory wraps csaf.Advisory with pre-built lookup map for O(1) access.
type CSAFAdvisory struct {
	csaf.Advisory

	// Pre-built map: ProductID -> *Product
	productMap map[csaf.ProductID]*Product
}

// NewCSAFAdvisory creates a new CSAFAdvisory with pre-built lookup map.
func NewCSAFAdvisory(adv csaf.Advisory) CSAFAdvisory {
	a := CSAFAdvisory{
		Advisory:   adv,
		productMap: make(map[csaf.ProductID]*Product),
	}
	a.buildProductMap()
	return a
}

// buildProductMap pre-builds all product lookups by iterating over all relationships
// and branches in the ProductTree, resolving each ProductID to a Product.
//
// Note on duplicate product IDs:
//
//	There might be multiple products with the same ProductID in the ProductTree.
//	Based on our understanding, these duplicates should essentially represent the same product,
//	so retrieving the first occurrence is sufficient for our purposes.
//
// e.g.
//   - https://github.com/aquasecurity/vuln-list-redhat/blob/42df5998a5f20d1a1cb67978486fffd82e61c34e/csaf-vex/2004/cve-2004-0885.json#L272-L282
//   - https://github.com/aquasecurity/vuln-list-redhat/blob/42df5998a5f20d1a1cb67978486fffd82e61c34e/csaf-vex/2004/cve-2004-0885.json#L470-L480
func (a *CSAFAdvisory) buildProductMap() {
	pt := lo.FromPtr(a.ProductTree)

	// Step 1: Build relationship map
	relationshipMap := make(map[csaf.ProductID]*csaf.Relationship)
	if pt.RelationShips != nil {
		for _, rel := range *pt.RelationShips {
			if rel == nil {
				continue
			}
			fpn := lo.FromPtr(rel.FullProductName)
			if id := lo.FromPtr(fpn.ProductID); id != "" {
				relationshipMap[id] = rel
			}
		}
	}

	// Step 2: Build product helper map (ProductID -> ProductIdentificationHelper)
	productHelperMap := make(map[csaf.ProductID]*csaf.ProductIdentificationHelper)

	// From full product names
	if pt.FullProductNames != nil {
		for _, fpn := range *pt.FullProductNames {
			if fpn == nil {
				continue
			}
			if id := lo.FromPtr(fpn.ProductID); id != "" {
				if _, exists := productHelperMap[id]; !exists {
					productHelperMap[id] = fpn.ProductIdentificationHelper
				}
			}
		}
	}

	// From branches (recursively)
	var walkBranches func(csaf.Branches)
	walkBranches = func(branches csaf.Branches) {
		for _, b := range branches {
			if b == nil {
				continue
			}
			if fpn := b.Product; fpn != nil {
				if id := lo.FromPtr(fpn.ProductID); id != "" {
					if _, exists := productHelperMap[id]; !exists {
						productHelperMap[id] = fpn.ProductIdentificationHelper
					}
				}
			}
			walkBranches(b.Branches)
		}
	}
	walkBranches(pt.Branches)

	// Step 3: Build final product map by resolving all relationships
	for productID, rel := range relationshipMap {
		product := a.resolveProduct(productID, rel, relationshipMap, productHelperMap)
		if product != nil {
			a.productMap[productID] = product
		}
	}
}

// resolveProduct resolves a ProductID to a Product using the pre-built maps.
func (a *CSAFAdvisory) resolveProduct(
	productID csaf.ProductID,
	rel *csaf.Relationship,
	relationshipMap map[csaf.ProductID]*csaf.Relationship,
	productHelperMap map[csaf.ProductID]*csaf.ProductIdentificationHelper,
) *Product {
	// Get PURL from product_reference
	// According to the documentation, the product_version object should always include PURL.
	// cf. https://redhatproductsecurity.github.io/security-data-guidelines/csaf-vex/
	// However, there is a known discrepancy where some product_version objects lack a PURL.
	// e.g. https://github.com/aquasecurity/vuln-list-redhat/blob/42df5998a5f20d1a1cb67978486fffd82e61c34e/csaf-vex/2016/cve-2016-3674.json#L330-L336
	// In such cases, we generate a pseudo-PURL.
	var purlString string
	productRef := lo.FromPtr(rel.ProductReference)
	if helper := productHelperMap[productRef]; helper != nil && helper.PURL != nil {
		purlString = string(*helper.PURL)
	} else {
		purlString = "pkg:rpm/redhat/" + string(productID)
	}

	purl, err := packageurl.FromString(purlString)
	if err != nil {
		return nil
	}

	// Get CPE and module from relates_to_product_reference
	cpe, module := a.resolveRelatesToProductReference(
		lo.FromPtr(rel.RelatesToProductReference),
		relationshipMap,
		productHelperMap,
	)

	// Extract module information from the "rpmmod" qualifier if present.
	// Red Hat changed the PURL format from "pkg:rpmmod/redhat/..." to "pkg:rpm/redhat/...?rpmmod=..."
	// cf. https://issues.redhat.com/browse/SECDATA-1115
	if module == "" {
		if rpmmod := purl.Qualifiers.Map()["rpmmod"]; rpmmod != "" {
			// rpmmod = "389-ds:1.4:8100020240613122040:25e700aa"
			// module = "389-ds:1.4"
			parts := strings.SplitN(rpmmod, ":", 3)
			if len(parts) >= 2 {
				module = parts[0] + ":" + parts[1]
			}
		}
	}

	return &Product{
		Module:  module,
		Package: purl,
		Stream:  cpe,
	}
}

// resolveRelatesToProductReference resolves the CPE and module for a relates_to_product_reference.
func (a *CSAFAdvisory) resolveRelatesToProductReference(
	productID csaf.ProductID,
	relationshipMap map[csaf.ProductID]*csaf.Relationship,
	productHelperMap map[csaf.ProductID]*csaf.ProductIdentificationHelper,
) (csaf.CPE, string) {
	// Check if the package is a module (has its own relationship)
	if rel := relationshipMap[productID]; rel != nil {
		return a.resolveModule(rel, relationshipMap, productHelperMap)
	}

	// Otherwise, get CPE directly from product helper
	if helper := productHelperMap[productID]; helper != nil && helper.CPE != nil {
		return *helper.CPE, ""
	}

	return "", ""
}

// resolveModule resolves module information for a modular package.
// e.g.
//
//	{
//	  "category": "default_component_of",
//	  "full_product_name": {
//	    "name": "httpd:2.4:8070020230131172653:bd1311ed as a component of Red Hat Enterprise Linux AppStream (v. 8)",
//	    "product_id": "AppStream-8.7.0.Z.MAIN:httpd:2.4:8070020230131172653:bd1311ed"
//	  },
//	  "product_reference": "httpd:2.4:8070020230131172653:bd1311ed",
//	  "relates_to_product_reference": "AppStream-8.7.0.Z.MAIN"
//	}
func (a *CSAFAdvisory) resolveModule(
	relationship *csaf.Relationship,
	relationshipMap map[csaf.ProductID]*csaf.Relationship,
	productHelperMap map[csaf.ProductID]*csaf.ProductIdentificationHelper,
) (csaf.CPE, string) {
	productRef := lo.FromPtr(relationship.ProductReference)
	if productRef == "" {
		return "", ""
	}

	// Look up the module stream
	moduleHelper := productHelperMap[productRef]
	if moduleHelper == nil || moduleHelper.PURL == nil {
		return "", ""
	}

	purl, err := packageurl.FromString(string(*moduleHelper.PURL))
	if err != nil {
		return "", ""
	}
	if purl.Type != "rpmmod" {
		return "", ""
	}

	ver, _, _ := strings.Cut(purl.Version, ":")
	module := fmt.Sprintf("%s:%s", purl.Name, ver)

	// Look up the product stream (recursively)
	cpe, _ := a.resolveRelatesToProductReference(
		lo.FromPtr(relationship.RelatesToProductReference),
		relationshipMap,
		productHelperMap,
	)

	return cpe, module
}

// LookUpProduct returns the pre-computed Product for a given ProductID.
func (a CSAFAdvisory) LookUpProduct(productID csaf.ProductID) (*Product, error) {
	return a.productMap[productID], nil
}
