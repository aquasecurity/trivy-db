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
	Julia      Type = "julia"
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
	Alpine      Type = "alpine"
	RedHat      Type = "redhat"
	Debian      Type = "debian"
	Ubuntu      Type = "ubuntu"
	CentOS      Type = "centos"
	Rocky       Type = "rocky"
	Fedora      Type = "fedora"
	AmazonLinux Type = "amazon"
	OracleLinux Type = "oracle"
	SUSE        Type = "suse"
	ArchLinux   Type = "archlinux"
	AlmaLinux   Type = "alma"
	AzureLinux  Type = "azure-linux"
	CBLMariner  Type = "cbl-mariner"
	PhotonOS    Type = "photon"
	Wolfi       Type = "wolfi"
	Chainguard  Type = "chainguard"
	Echo        Type = "echo"
	MinimOS     Type = "minimos"
	Seal        Type = "seal"
)

// String returns the string representation of the ecosystem type
func (t Type) String() string {
	return string(t)
}
