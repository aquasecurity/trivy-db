package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

func CacheDir() string {
	tmpDir, err := os.UserCacheDir()
	if err != nil {
		tmpDir = os.TempDir()
	}
	return filepath.Join(tmpDir, "trivy-db")
}

func ConstructVersion(epoch, version, release string) string {
	verStr := ""
	if epoch != "0" && epoch != "" {
		verStr += fmt.Sprintf("%s:", epoch)
	}
	verStr += version

	if release != "" {
		verStr += fmt.Sprintf("-%s", release)

	}
	return verStr
}

func NormalizePkgName(ecosystem types.Ecosystem, pkgName string) string {
	if ecosystem == vulnerability.Pip {
		// from https://www.python.org/dev/peps/pep-0426/#name
		// All comparisons of distribution names MUST be case insensitive,
		// and MUST consider hyphens and underscores to be equivalent.
		pkgName = strings.ToLower(pkgName)
		pkgName = strings.ReplaceAll(pkgName, "_", "-")
	} else if ecosystem != vulnerability.NuGet { // Nuget is case-sensitive
		pkgName = strings.ToLower(pkgName)
	}
	return pkgName
}
