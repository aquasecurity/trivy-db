package redhatcsaf

import (
	"fmt"
	"strings"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"github.com/samber/oops"
)

type CSAFAdvisory struct {
	csaf.Advisory
}

func (a CSAFAdvisory) LookUpProduct(productID csaf.ProductID) (*Product, error) {
	eb := oops.Code("lookup_error").With("product_id", productID)
	rel := a.LookUpRelationship(productID)
	if rel == nil { // Not supported
		return nil, nil
	}

	// Look up product_reference
	var purlString string
	if pkg, err := a.LookUpProductReference(lo.FromPtr(rel.ProductReference)); err != nil {
		return nil, eb.Wrap(err)
	} else if pkg == nil || pkg.PURL == nil {
		// According to the documentation, the product_version object should always include PURL.
		// cf. https://redhatproductsecurity.github.io/security-data-guidelines/csaf-vex/
		// However, there is a known discrepancy where some product_version objects lack a PURL.
		// e.g. https://github.com/aquasecurity/vuln-list-redhat/blob/42df5998a5f20d1a1cb67978486fffd82e61c34e/csaf-vex/2016/cve-2016-3674.json#L330-L336
		// In such cases, we generate a pseudo-PURL.
		purlString = "pkg:rpm/redhat/" + string(productID)
	} else {
		purlString = string(*pkg.PURL)
	}

	purl, err := packageurl.FromString(purlString)
	if err != nil {
		return nil, eb.Wrapf(err, "invalid purl")
	}

	// Look up relates_to_product_reference
	cpe, module, err := a.LookUpRelatesToProductReference(lo.FromPtr(rel.RelatesToProductReference))
	if err != nil {
		return nil, eb.Wrap(err)
	}

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
	}, nil
}

func (a CSAFAdvisory) LookUpProductReference(productID csaf.ProductID) (*csaf.ProductIdentificationHelper, error) {
	eb := oops.Tags("product_reference").With("product_reference", productID)
	productReference, found := a.findProductIdentificationHelper(productID, a.ProductTree)
	if !found {
		return nil, eb.Errorf("product reference not found")
	}
	return productReference, nil
}

func (a CSAFAdvisory) LookUpRelatesToProductReference(productID csaf.ProductID) (csaf.CPE, string, error) {
	eb := oops.Tags("relates_to_product_reference").With("relates_to_product_reference", productID)

	// Check if the package is a module
	rel := a.LookUpRelationship(productID)
	if rel != nil {
		return a.LookUpModule(rel)
	}

	product, err := a.LookUpProductReference(productID)
	if err != nil {
		return "", "", eb.Wrap(err)
	} else if product.CPE == nil {
		return "", "", eb.Errorf("stream CPE not found")
	}

	return *product.CPE, "", nil
}

// LookUpModule looks up the module information for a given relationship.
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
//	 }
func (a CSAFAdvisory) LookUpModule(relationship *csaf.Relationship) (csaf.CPE, string, error) {
	eb := oops.Tags("lookup_module")
	if lo.FromPtr(relationship.ProductReference) == "" {
		return "", "", eb.Wrapf(errUnexpectedRecord, "empty product reference")
	}
	eb = eb.With("product_reference", *relationship.ProductReference)

	// Look up the module stream
	moduleRef, err := a.LookUpProductReference(*relationship.ProductReference)
	if err != nil {
		return "", "", eb.Wrap(err)
	} else if moduleRef == nil || moduleRef.PURL == nil {
		return "", "", eb.Wrapf(errUnexpectedRecord, "module purl not found")
	}
	eb = eb.With("module_purl", *moduleRef.PURL)

	purl, err := packageurl.FromString(string(*moduleRef.PURL))
	if err != nil {
		return "", "", eb.Wrapf(err, "invalid purl")
	} else if purl.Type != "rpmmod" { // Must be "rpmmod" for modular streams
		return "", "", eb.With("purl_type", purl.Type).Wrapf(errUnexpectedRecord, "unexpected purl type")
	}

	ver, _, _ := strings.Cut(purl.Version, ":") // e.g. "2.4:8070020230131172653:bd1311ed" => "2.4"
	module := fmt.Sprintf("%s:%s", purl.Name, ver)
	eb = eb.With("module", module)

	// Look up the product stream
	cpe, _, err := a.LookUpRelatesToProductReference(lo.FromPtr(relationship.RelatesToProductReference))
	if err != nil {
		return "", "", eb.Wrap(err)
	}

	return cpe, module, nil
}

func (a CSAFAdvisory) LookUpRelationship(productID csaf.ProductID) *csaf.Relationship {
	for _, rel := range a.Relationships() {
		fpn := lo.FromPtr(rel.FullProductName)
		if lo.FromPtr(fpn.ProductID) == productID {
			return rel
		}
	}
	return nil
}

func (a CSAFAdvisory) Relationships() []*csaf.Relationship {
	pt := lo.FromPtr(a.ProductTree)
	return lo.Filter(lo.FromPtr(pt.RelationShips), func(r *csaf.Relationship, _ int) bool {
		return r != nil
	})
}

// findProductIdentificationHelper returns the first ProductIdentificationHelper matching a given ProductID
// by iterating over all full product names and branches recursively available in the ProductTree.
//
// Note on duplicate product ids:
//
//	There might be multiple products with the same ProductID in the ProductTree.
//	Based on our understanding, these duplicates should essentially represent the same product,
//	so retrieving the first occurrence is sufficient for our purposes.
//
// e.g.
//   - https://github.com/aquasecurity/vuln-list-redhat/blob/42df5998a5f20d1a1cb67978486fffd82e61c34e/csaf-vex/2004/cve-2004-0885.json#L272-L282
//   - https://github.com/aquasecurity/vuln-list-redhat/blob/42df5998a5f20d1a1cb67978486fffd82e61c34e/csaf-vex/2004/cve-2004-0885.json#L470-L480
func (a CSAFAdvisory) findProductIdentificationHelper(id csaf.ProductID, pt *csaf.ProductTree) (*csaf.ProductIdentificationHelper, bool) {
	// Iterate over all full product names
	if fpns := pt.FullProductNames; fpns != nil {
		for _, fpn := range *fpns {
			if fpn != nil && lo.FromPtr(fpn.ProductID) == id {
				return fpn.ProductIdentificationHelper, true
			}
		}
	}

	// Iterate over branches recursively
	var recBranch func(csaf.Branches) (*csaf.ProductIdentificationHelper, bool)
	recBranch = func(branches csaf.Branches) (*csaf.ProductIdentificationHelper, bool) {
		for _, b := range branches {
			if fpn := b.Product; fpn != nil && lo.FromPtr(fpn.ProductID) == id {
				return fpn.ProductIdentificationHelper, true
			}
			if h, found := recBranch(b.Branches); found {
				return h, true
			}
		}
		return nil, false
	}

	return recBranch(pt.Branches)
}
