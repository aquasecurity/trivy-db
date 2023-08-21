package osv

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/types"
)

func FilterCveIDs(aliases []string) []string {
	var cveIDs []string
	for _, a := range aliases {
		if strings.HasPrefix(a, "CVE-") {
			cveIDs = append(cveIDs, a)
		}
	}
	return cveIDs
}

func GetAdvisory(affected Affected) types.Advisory {
	var patchedVersions, vulnerableVersions []string

	for _, affects := range affected.Ranges {
		if affects.Type == RangeTypeGit {
			continue
		}

		var vulnerable string
		for _, event := range affects.Events {
			switch {
			case event.Introduced != "":
				// e.g. {"introduced": "1.2.0}, {"introduced": "2.2.0}
				if vulnerable != "" {
					vulnerableVersions = append(vulnerableVersions, vulnerable)
				}
				vulnerable = fmt.Sprintf(">=%s", event.Introduced)
			case event.Fixed != "":
				// patched versions
				patchedVersions = append(patchedVersions, event.Fixed)

				// e.g. {"introduced": "1.2.0}, {"fixed": "1.2.5}
				vulnerable = fmt.Sprintf("%s, <%s", vulnerable, event.Fixed)
			}
		}
		if vulnerable != "" {
			vulnerableVersions = append(vulnerableVersions, vulnerable)
		}
	}

	for _, v := range affected.Versions {
		vulnerableVersions = append(vulnerableVersions, fmt.Sprintf("=%s", v))
	}

	return types.Advisory{
		VulnerableVersions: vulnerableVersions,
		PatchedVersions:    patchedVersions,
	}
}
