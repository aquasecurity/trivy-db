package susecsaf

// Advisory is the subset of a SUSE CSAF document used by trivy-db.
//
// vuln-list-suse stores the documents as-is, and SUSE's feed is not always schema-conformant.
// For example, some CPEs in product_tree carry unescaped characters ("cpe:/o:novell,inc:OES:23.4", "cpe:2.3:a:qemu:qemu:1.0.0+:*:*:*:*:*:*:*").
// The csaf package validates many values while decoding (CPEs, CVE IDs, CVSS vectors, enums and more) and rejects the whole document if one of them is invalid.
// To keep such documents, only the fields trivy-db reads are decoded, into plain types without validation.
type Advisory struct {
	Document        Document        `json:"document"`
	ProductTree     ProductTree     `json:"product_tree"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Document struct {
	Title             string            `json:"title"`
	Tracking          Tracking          `json:"tracking"`
	Notes             []Note            `json:"notes"`
	References        []Reference       `json:"references"`
	AggregateSeverity AggregateSeverity `json:"aggregate_severity"`
}

type Tracking struct {
	ID string `json:"id"`
}

type Note struct {
	Category string `json:"category"`
	Text     string `json:"text"`
}

type Reference struct {
	URL string `json:"url"`
}

type AggregateSeverity struct {
	Text string `json:"text"`
}

type ProductTree struct {
	Relationships []Relationship `json:"relationships"`
}

type Relationship struct {
	FullProductName           FullProductName `json:"full_product_name"`
	ProductReference          string          `json:"product_reference"`
	RelatesToProductReference string          `json:"relates_to_product_reference"`
}

type FullProductName struct {
	ProductID string `json:"product_id"`
}

type Vulnerability struct {
	ProductStatus ProductStatus `json:"product_status"`
	Threats       []Threat      `json:"threats"`
}

type ProductStatus struct {
	Fixed       []string `json:"fixed"`
	Recommended []string `json:"recommended"`
}

type Threat struct {
	Category string `json:"category"`
	Details  string `json:"details"`
}

type Package struct {
	Name         string
	FixedVersion string
}

type AffectedPackage struct {
	Package Package
	OSVer   string
}
