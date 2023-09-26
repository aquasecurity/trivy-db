package bucket

import (
	"fmt"

	"github.com/aquasecurity/trivy-db/pkg/types"
)

const separator = "::"

<<<<<<< HEAD
func Name(ecosystem types.Ecosystem, dataSource string) string {
	return fmt.Sprintf("%s%s%s", ecosystem, separator, dataSource)
=======
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
	case "erlang":
		prefix = vulnerability.Erlang
	case "pub":
		prefix = vulnerability.Pub
	case "swift":
		prefix = vulnerability.Swift
	case "cocoapods":
		prefix = vulnerability.Cocoapods
	case "bitnami":
		prefix = vulnerability.Bitnami
	case "kubernetes":
		prefix = vulnerability.Kubernetes
	default:
		return ""
	}
	return fmt.Sprintf("%s%s%s", prefix, separator, dataSource)
>>>>>>> 9df5b28 (feat: add k8s cves)
}
