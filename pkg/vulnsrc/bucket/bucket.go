package bucket

import (
	"fmt"

	"github.com/samber/lo"
	"github.com/samber/oops"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/types"
)

const separator = "::"

// Bucket interface for generating bucket names and identifying ecosystems
type Bucket interface {
	Name() string
	Ecosystem() ecosystem.Type
}

// DataSourceBucket interface for buckets that provide data source information
type DataSourceBucket interface {
	Bucket
	DataSource() types.DataSource
}

// osBucket for OS ecosystems (Alpine, RedHat, etc.)
type osBucket struct {
	ecosystem ecosystem.Type
	version   string
}

func (o osBucket) Name() string {
	if o.version == "" {
		return o.ecosystem.String()
	}
	return o.ecosystem.String() + " " + o.version
}

func (o osBucket) Ecosystem() ecosystem.Type {
	return o.ecosystem
}

// langBucket for language ecosystems (Go, npm, etc.)
type langBucket struct {
	ecosystem  ecosystem.Type
	dataSource types.DataSource
}

func (l langBucket) Name() string {
	return l.ecosystem.String() + separator + l.dataSource.Name
}

func (l langBucket) Ecosystem() ecosystem.Type {
	return l.ecosystem
}

func (l langBucket) DataSource() types.DataSource {
	return l.dataSource
}

// newOS creates a bucket for OS ecosystems
func newOS(ecoType ecosystem.Type, version string) osBucket {
	return osBucket{
		ecosystem: ecoType,
		version:   version,
	}
}

// newLang creates a bucket for language ecosystems
func newLang(ecoType ecosystem.Type, dataSource types.DataSource) (DataSourceBucket, error) {
	if lo.IsEmpty(dataSource) {
		return nil, oops.With("ecosystem", ecoType).Errorf("data source cannot be empty")
	}
	return langBucket{
		ecosystem:  ecoType,
		dataSource: dataSource,
	}, nil
}

/////////////////////////
// Standard OS buckets //
/////////////////////////

// NewAlma creates a bucket for Alma Linux
func NewAlma(version string) Bucket { return newOS(ecosystem.AlmaLinux, version) }

// NewAlpine creates a bucket for Alpine Linux
func NewAlpine(version string) Bucket { return newOS(ecosystem.Alpine, version) }

// NewArchLinux creates a bucket for Arch Linux
func NewArchLinux(version string) Bucket { return newOS(ecosystem.ArchLinux, version) }

// NewChainguard creates a bucket for Chainguard
func NewChainguard(version string) Bucket { return newOS(ecosystem.Chainguard, version) }

// NewDebian creates a bucket for Debian
func NewDebian(version string) Bucket { return newOS(ecosystem.Debian, version) }

// NewEcho creates a bucket for Echo
func NewEcho(version string) Bucket { return newOS(ecosystem.Echo, version) }

// NewMinimOS creates a bucket for MinimOS
func NewMinimOS(version string) Bucket { return newOS(ecosystem.MinimOS, version) }

// NewRocky creates a bucket for Rocky Linux
func NewRocky(version string) Bucket { return newOS(ecosystem.Rocky, version) }

// NewUbuntu creates a bucket for Ubuntu
func NewUbuntu(version string) Bucket { return newOS(ecosystem.Ubuntu, version) }

// NewWolfi creates a bucket for Wolfi
func NewWolfi(version string) Bucket { return newOS(ecosystem.Wolfi, version) }

//////////////////////////////////////////////////////////////////////
// OS buckets with special naming conventions (alphabetical order)  //
//////////////////////////////////////////////////////////////////////

// amazonBucket for Amazon Linux with special naming convention
type amazonBucket struct {
	osBucket
}

func (a amazonBucket) Name() string {
	return "amazon linux " + a.version
}

// NewAmazon creates a bucket for Amazon Linux
func NewAmazon(version string) Bucket {
	return amazonBucket{newOS(ecosystem.AmazonLinux, version)}
}

// azureLinuxBucket for Azure Linux with special naming convention
type azureLinuxBucket struct {
	osBucket
}

func (a azureLinuxBucket) Name() string {
	return "Azure Linux " + a.version
}

// NewAzureLinux creates a bucket for Azure Linux
func NewAzureLinux(version string) Bucket {
	return azureLinuxBucket{newOS(ecosystem.AzureLinux, version)}
}

// marinerBucket for CBL-Mariner with special naming convention
type marinerBucket struct {
	osBucket
}

func (m marinerBucket) Name() string {
	return "CBL-Mariner " + m.version
}

// NewMariner creates a bucket for CBL-Mariner
func NewMariner(version string) Bucket {
	return marinerBucket{newOS(ecosystem.CBLMariner, version)}
}

// oracleBucket for Oracle Linux with special naming convention
type oracleBucket struct {
	osBucket
}

func (o oracleBucket) Name() string {
	// cat /etc/os-release ORACLE_BUGZILLA_PRODUCT="Oracle Linux 8"
	return "Oracle Linux " + o.version
}

// NewOracle creates a bucket for Oracle Linux
func NewOracle(version string) Bucket { return oracleBucket{newOS(ecosystem.OracleLinux, version)} }

// redHatBucket for Red Hat with special naming convention
type redHatBucket struct {
	osBucket
}

func (r redHatBucket) Name() string {
	name := "Red Hat"
	if r.version == "" {
		return name
	}
	return name + " " + r.version
}

// NewRedHat creates a bucket for Red Hat
func NewRedHat(version string) Bucket { return redHatBucket{newOS(ecosystem.RedHat, version)} }

// photonBucket for PhotonOS OS with special naming convention
type photonBucket struct {
	osBucket
}

func (p photonBucket) Name() string {
	return "Photon OS " + p.version
}

// NewPhoton creates a bucket for PhotonOS OS
func NewPhoton(version string) Bucket { return photonBucket{newOS(ecosystem.PhotonOS, version)} }

// openSUSEBucket for openSUSE with special naming convention
type openSUSEBucket struct {
	osBucket
}

func (o openSUSEBucket) Name() string {
	return "openSUSE Leap " + o.version
}

// openSUSETumbleweedBucket for openSUSE Tumbleweed with special naming convention
type openSUSETumbleweedBucket struct {
	osBucket
}

func (o openSUSETumbleweedBucket) Name() string {
	return "openSUSE Tumbleweed"
}

// openSUSELeapMicroBucket for openSUSE Leap Micro with special naming convention
type openSUSELeapMicroBucket struct {
	osBucket
}

func (o openSUSELeapMicroBucket) Name() string {
	return "openSUSE Leap Micro " + o.version
}

// suseLinuxEnterpriseBucket for SUSE Linux Enterprise with special naming convention
type suseLinuxEnterpriseBucket struct {
	osBucket
}

func (s suseLinuxEnterpriseBucket) Name() string {
	return "SUSE Linux Enterprise " + s.version
}

// suseLinuxEnterpriseMicroBucket for SUSE Linux Enterprise Micro with special naming convention
type suseLinuxEnterpriseMicroBucket struct {
	osBucket
}

func (s suseLinuxEnterpriseMicroBucket) Name() string {
	return "SUSE Linux Enterprise Micro " + s.version
}

// NewOpenSUSE creates a bucket for openSUSE Leap
func NewOpenSUSE(version string) Bucket {
	return openSUSEBucket{newOS(ecosystem.SUSE, version)}
}

// NewOpenSUSETumbleweed creates a bucket for openSUSE Tumbleweed
func NewOpenSUSETumbleweed() Bucket {
	return openSUSETumbleweedBucket{newOS(ecosystem.SUSE, "")}
}

// NewOpenSUSELeapMicro creates a bucket for openSUSE Leap Micro
func NewOpenSUSELeapMicro(version string) Bucket {
	return openSUSELeapMicroBucket{newOS(ecosystem.SUSE, version)}
}

// NewSUSELinuxEnterprise creates a bucket for SUSE Linux Enterprise
func NewSUSELinuxEnterprise(version string) Bucket {
	return suseLinuxEnterpriseBucket{newOS(ecosystem.SUSE, version)}
}

// NewSUSELinuxEnterpriseMicro creates a bucket for SUSE Linux Enterprise Micro
func NewSUSELinuxEnterpriseMicro(version string) Bucket {
	return suseLinuxEnterpriseMicroBucket{newOS(ecosystem.SUSE, version)}
}

// sealBucket for Seal ecosystem with special naming convention
type sealBucket struct {
	base       Bucket
	dataSource types.DataSource
}

func (p sealBucket) Name() string {
	return fmt.Sprintf("seal %s", p.base.Name())
}
func (p sealBucket) Ecosystem() ecosystem.Type {
	return p.base.Ecosystem()
}
func (p sealBucket) DataSource() types.DataSource {
	return p.dataSource
}

// NewSeal creates a bucket for Seal ecosystem
func NewSeal(baseEco ecosystem.Type, baseEcoVer string, dataSource types.DataSource) (Bucket, error) {
	bkt := sealBucket{
		dataSource: dataSource,
	}
	switch baseEco {
	case ecosystem.Alpine:
		bkt.base = NewAlpine("")
	case ecosystem.Debian:
		bkt.base = NewDebian("")
	case ecosystem.RedHat:
		bkt.base = NewRedHat(baseEcoVer)
	default:
		return nil, oops.With("base_ecosystem", baseEco).Errorf("unsupported base ecosystem for Seal bucket")
	}

	return bkt, nil
}

////////////////////////////////
// Language ecosystem buckets //
////////////////////////////////

// NewBitnami creates a bucket for Bitnami ecosystem with data source
func NewBitnami(dataSource types.DataSource) (DataSourceBucket, error) {
	return newLang(ecosystem.Bitnami, dataSource)
}

// NewCargo creates a bucket for Cargo ecosystem with data source
func NewCargo(dataSource types.DataSource) (DataSourceBucket, error) {
	return newLang(ecosystem.Cargo, dataSource)
}

// NewCocoapods creates a bucket for Cocoapods ecosystem with data source
func NewCocoapods(dataSource types.DataSource) (DataSourceBucket, error) {
	return newLang(ecosystem.Cocoapods, dataSource)
}

// NewConan creates a bucket for Conan ecosystem with data source
func NewConan(dataSource types.DataSource) (DataSourceBucket, error) {
	return newLang(ecosystem.Conan, dataSource)
}

// NewComposer creates a bucket for Composer ecosystem with data source
func NewComposer(dataSource types.DataSource) (DataSourceBucket, error) {
	return newLang(ecosystem.Composer, dataSource)
}

// NewErlang creates a bucket for Erlang ecosystem with data source
func NewErlang(dataSource types.DataSource) (DataSourceBucket, error) {
	return newLang(ecosystem.Erlang, dataSource)
}

// NewGo creates a bucket for Go ecosystem with data source
func NewGo(dataSource types.DataSource) (DataSourceBucket, error) {
	return newLang(ecosystem.Go, dataSource)
}

// NewKubernetes creates a bucket for Kubernetes ecosystem with data source
func NewKubernetes(dataSource types.DataSource) (DataSourceBucket, error) {
	return newLang(ecosystem.Kubernetes, dataSource)
}

// NewMaven creates a bucket for Maven ecosystem with data source
func NewMaven(dataSource types.DataSource) (DataSourceBucket, error) {
	return newLang(ecosystem.Maven, dataSource)
}

// NewNpm creates a bucket for npm ecosystem with data source
func NewNpm(dataSource types.DataSource) (DataSourceBucket, error) {
	return newLang(ecosystem.Npm, dataSource)
}

// NewNuGet creates a bucket for NuGet ecosystem with data source
func NewNuGet(dataSource types.DataSource) (DataSourceBucket, error) {
	return newLang(ecosystem.NuGet, dataSource)
}

// NewPub creates a bucket for Pub ecosystem with data source
func NewPub(dataSource types.DataSource) (DataSourceBucket, error) {
	return newLang(ecosystem.Pub, dataSource)
}

// NewPyPI creates a bucket for PyPI ecosystem with data source
func NewPyPI(dataSource types.DataSource) (DataSourceBucket, error) {
	return newLang(ecosystem.Pip, dataSource)
}

// NewRubyGems creates a bucket for RubyGems ecosystem with data source
func NewRubyGems(dataSource types.DataSource) (DataSourceBucket, error) {
	return newLang(ecosystem.RubyGems, dataSource)
}

// NewSwift creates a bucket for Swift ecosystem with data source
func NewSwift(dataSource types.DataSource) (DataSourceBucket, error) {
	return newLang(ecosystem.Swift, dataSource)
}
