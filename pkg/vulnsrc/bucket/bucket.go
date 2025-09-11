package bucket

import (
	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/types"
)

const separator = "::"

// Bucket interface for generating bucket names
type Bucket interface {
	Name() string
	Ecosystem() ecosystem.Type
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

func (o osBucket) DataSource() types.DataSource {
	return types.DataSource{}
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
func newOS(ecoType ecosystem.Type, version string) Bucket {
	return osBucket{ecosystem: ecoType, version: version}
}

// NewAlpine creates a bucket for Alpine Linux
func NewAlpine(version string) Bucket { return newOS(ecosystem.Alpine, version) }

// NewRedHat creates a bucket for Red Hat
func NewRedHat(version string) Bucket { return newOS(ecosystem.RedHat, version) }

// newLang creates a bucket for language ecosystems
func newLang(ecoType ecosystem.Type, dataSource types.DataSource) Bucket {
	return langBucket{ecosystem: ecoType, dataSource: dataSource}
}

// NewGo creates a bucket for Go ecosystem with data source
func NewGo(dataSource types.DataSource) Bucket { return newLang(ecosystem.Go, dataSource) }

// NewNpm creates a bucket for npm ecosystem with data source
func NewNpm(dataSource types.DataSource) Bucket { return newLang(ecosystem.Npm, dataSource) }

// NewPyPI creates a bucket for PyPI ecosystem with data source
func NewPyPI(dataSource types.DataSource) Bucket { return newLang(ecosystem.Pip, dataSource) }

// NewComposer creates a bucket for Composer ecosystem with data source
func NewComposer(dataSource types.DataSource) Bucket { return newLang(ecosystem.Composer, dataSource) }

// NewRubyGems creates a bucket for RubyGems ecosystem with data source
func NewRubyGems(dataSource types.DataSource) Bucket { return newLang(ecosystem.RubyGems, dataSource) }

// NewCargo creates a bucket for Cargo ecosystem with data source
func NewCargo(dataSource types.DataSource) Bucket { return newLang(ecosystem.Cargo, dataSource) }

// NewNuGet creates a bucket for NuGet ecosystem with data source
func NewNuGet(dataSource types.DataSource) Bucket { return newLang(ecosystem.NuGet, dataSource) }

// NewMaven creates a bucket for Maven ecosystem with data source
func NewMaven(dataSource types.DataSource) Bucket { return newLang(ecosystem.Maven, dataSource) }

// NewConan creates a bucket for Conan ecosystem with data source
func NewConan(dataSource types.DataSource) Bucket { return newLang(ecosystem.Conan, dataSource) }

// NewErlang creates a bucket for Erlang ecosystem with data source
func NewErlang(dataSource types.DataSource) Bucket { return newLang(ecosystem.Erlang, dataSource) }

// NewPub creates a bucket for Pub ecosystem with data source
func NewPub(dataSource types.DataSource) Bucket { return newLang(ecosystem.Pub, dataSource) }

// NewSwift creates a bucket for Swift ecosystem with data source
func NewSwift(dataSource types.DataSource) Bucket { return newLang(ecosystem.Swift, dataSource) }

// NewCocoapods creates a bucket for Cocoapods ecosystem with data source
func NewCocoapods(dataSource types.DataSource) Bucket { return newLang(ecosystem.Cocoapods, dataSource) }

// NewBitnami creates a bucket for Bitnami ecosystem with data source
func NewBitnami(dataSource types.DataSource) Bucket { return newLang(ecosystem.Bitnami, dataSource) }

// NewKubernetes creates a bucket for Kubernetes ecosystem with data source
func NewKubernetes(dataSource types.DataSource) Bucket { return newLang(ecosystem.Kubernetes, dataSource) }

