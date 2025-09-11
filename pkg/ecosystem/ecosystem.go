package ecosystem

// Type represents an ecosystem identifier (stable slug)
type Type string

const (
	Unknown Type = "unknown"

	// Language ecosystems
	Npm        Type = "npm"
	Composer   Type = "composer"
	Pip        Type = "pip"
	RubyGems   Type = "rubygems"
	Cargo      Type = "cargo"
	NuGet      Type = "nuget"
	Maven      Type = "maven"
	Go         Type = "go"
	Conan      Type = "conan"
	Erlang     Type = "erlang"
	Pub        Type = "pub"
	Swift      Type = "swift"
	Cocoapods  Type = "cocoapods"
	Bitnami    Type = "bitnami"
	Kubernetes Type = "k8s"

	// OS ecosystems
	Alpine     Type = "alpine"
	RedHat     Type = "redhat"
	Debian     Type = "debian"
	Ubuntu     Type = "ubuntu"
	CentOS     Type = "centos"
	Rocky      Type = "rocky"
	Fedora     Type = "fedora"
	Amazon     Type = "amazon"
	Oracle     Type = "oracle"
	SUSE       Type = "suse"
	ArchLinux  Type = "arch-linux"
	Alma       Type = "alma"
	AzureLinux Type = "azure"
	Photon     Type = "photon"
	Wolfi      Type = "wolfi"
	Chainguard Type = "chainguard"
)

// String returns the string representation of the ecosystem type
func (t Type) String() string {
	return string(t)
}

// All contains all supported ecosystems (for backward compatibility)
var All = []Type{
	Npm,
	Composer,
	Pip,
	RubyGems,
	Cargo,
	NuGet,
	Maven,
	Go,
	Conan,
	Erlang,
	Pub,
	Swift,
	Cocoapods,
	Bitnami,
	Kubernetes,
}
