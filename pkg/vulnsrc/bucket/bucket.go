package bucket

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"golang.org/x/xerrors"
)

const separator = "::"

var UnknownBucketErr = xerrors.New("unknown bucket error")

func BucketName(ecosystem, dataSource string) (string, error) {
	var prefix string
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
	case "cargo":
		prefix = vulnerability.Cargo
	default:
		// Expecting an error at the caller
		return "", UnknownBucketErr
	}
	return fmt.Sprintf("%s%s%s", prefix, separator, dataSource), nil
}
