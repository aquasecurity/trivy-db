package utils

import (
	"net/url"
	"strings"

	strutil "github.com/aquasecurity/trivy-db/pkg/utils/strings"
)

const (
	nvd     = "nvd.nist.gov"
	rustsec = "rustsec.org"
	ghsa    = "github.com"
)

func GetUniqueIDsFromReferences(refs []string, knownIDs []string) []string {
	condidates := map[string]interface{}{}
	for _, ref := range refs {
		u, err := url.Parse(ref)
		if err != nil {
			continue
		}
		id := ""
		switch u.Host {
		// https://rustsec.org/advisories/RUSTSEC-2021-0120.html"
		case rustsec:
			if strings.HasPrefix(u.Path, "/advisories/") {
				id = strings.TrimSuffix(strings.TrimPrefix(u.Path, "/advisories/"), ".html")
			}
		// https://nvd.nist.gov/vuln/detail/CVE-2021-45708
		case nvd:
			if strings.HasPrefix(u.Path, "/vuln/detail/") {
				id = strings.TrimPrefix(u.Path, "/vuln/detail/")
			}
		// https://github.com/advisories/GHSA-4qrp-27r3-66fj
		case ghsa:
			if strings.HasPrefix(u.Path, "/advisories/") {
				id = strings.TrimPrefix(u.Path, "/advisories/")
			}
		default:
			continue
		}
		if id != "" && !strutil.InSlice(id, knownIDs) {
			condidates[id] = struct{}{}
		}
	}
	ids := []string{}
	for k := range condidates {
		ids = append(ids, k)
	}
	return ids
}
