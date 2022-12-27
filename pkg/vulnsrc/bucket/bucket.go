package bucket

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const separator = "::"

func Name(ecosystem, dataSource string) string {
	var prefix types.Ecosystem
	switch strings.ToLower(ecosystem) {
	case "go", "golang":
		prefix = vulnerability.Go
	case "maven", "gradle":
		prefix = vulnerability.Maven
	case "npm", "yarn":
		prefix = vulnerability.Npm
	case "packagist", "composer":
		prefix = vulnerability.Composer
	case "pypi", "pip", "pipenv", "poetry":
		prefix = vulnerability.Pip
	case "gem", "bundler", "rubygems":
		prefix = vulnerability.RubyGems
	case "nuget":
		prefix = vulnerability.NuGet
	case "conan":
		prefix = vulnerability.Conan
	case "cargo", "rust":
		prefix = vulnerability.Cargo
	case "pub":
		prefix = vulnerability.Pub
	default:
		return ""
	}
	return fmt.Sprintf("%s%s%s", prefix, separator, dataSource)
}
