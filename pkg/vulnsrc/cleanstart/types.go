package cleanstart

import (
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/osv"
)

// ecosystemName is the value CleanStart puts in `affected[].package.ecosystem`.
// It is matched case-insensitively because the feed has shipped both "CleanStart"
// and "cleanstart".
const ecosystemName = "cleanstart"

// rangeTypeEcosystem is the only range type CleanStart emits. Advisories carry APK
// version ranges, so GIT and SEMVER ranges are ignored if they ever show up.
const rangeTypeEcosystem osv.RangeType = "ECOSYSTEM"

// entry is one (vulnerability ID, package) pair ready to be written to the DB.
// A single advisory expands into many: it may list several upstream IDs and always
// lists every package that received the fix.
type entry struct {
	vulnID   string
	pkgName  string
	advisory types.Advisory
	detail   types.VulnerabilityDetail
}
