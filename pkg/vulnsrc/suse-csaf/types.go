package susecsaf

import "github.com/gocsaf/csaf/v3/csaf"

// Advisory is the subset of a SUSE CSAF document used by trivy-db.
//
// vuln-list-suse stores the documents as-is, and SUSE's feed is not always schema-conformant:
// some CPEs in product_tree.branches carry unescaped characters (e.g. "cpe:/o:novell,inc:OES:23.4",
// "cpe:2.3:a:qemu:qemu:1.0.0+:*:*:*:*:*:*:*"), and csaf.Advisory rejects the whole document
// because of them. Only the parts that are needed are decoded, so these documents are still
// processed.
type Advisory struct {
	Document        *csaf.Document       `json:"document"`
	ProductTree     *ProductTree         `json:"product_tree"`
	Vulnerabilities csaf.Vulnerabilities `json:"vulnerabilities"`
}

type ProductTree struct {
	Relationships []Relationship `json:"relationships"`
}

// Relationship mirrors csaf.Relationship without full_product_name.product_identification_helper,
// which may hold a CPE.
type Relationship struct {
	FullProductName           FullProductName `json:"full_product_name"`
	ProductReference          csaf.ProductID  `json:"product_reference"`
	RelatesToProductReference csaf.ProductID  `json:"relates_to_product_reference"`
}

type FullProductName struct {
	ProductID csaf.ProductID `json:"product_id"`
}

type Package struct {
	Name         string
	FixedVersion string
}

type AffectedPackage struct {
	Package Package
	OSVer   string
}
