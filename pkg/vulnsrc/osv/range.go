package osv

import (
	"fmt"
	"github.com/aquasecurity/go-gem-version"
	"github.com/aquasecurity/go-npm-version/pkg"
	pep440 "github.com/aquasecurity/go-pep440-version"
	"github.com/aquasecurity/go-version/pkg/semver"
	"github.com/aquasecurity/go-version/pkg/version"
	"github.com/aquasecurity/trivy-db/pkg/log"
	mvn "github.com/masahiro331/go-mvn-version"
	"go.uber.org/zap"
)

type VersionRange interface {
	Contains(ver string) bool
	String() string
	SetFixed(fixed string)
	SetLastAffected(lastAffected string)
}

func NewVersionRange(ecosystem Ecosystem, from string) VersionRange {
	switch ecosystem {
	case EcosystemNpm:
		return NewNpmVersionRange(from)
	case EcosystemRubygems:
		return NewRubyGemsVersionRange(from)
	case EcosystemPyPI:
		return NewPyPIVersionRange(from)
	case EcosystemMaven:
		return NewMavenVersionRange(from)
	case EcosystemGo, EcosystemCrates, EcosystemPackagist, EcosystemNuGet:
		return NewSemVerRange(ecosystem, from)
	default:
		return NewDefaultVersionRange(ecosystem, from)
	}
}

// versionRange represents a range of versions
type versionRange struct {
	from       string
	to         string
	toIncluded bool
}

// constraint returns the range as a constraint string in the expected
// format for semver.NewConstraint
func (r *versionRange) String() string {
	// e.g. {"introduced": "1.2.0"}, {"last_affected": "1.2.0"}
	if r.toIncluded && r.from == r.to {
		return fmt.Sprintf("=%s", r.from)
	}

	var ver string
	if r.to != "" {
		ver = fmt.Sprintf("<%s", r.to)
		if r.toIncluded {
			ver = fmt.Sprintf("<=%s", r.to)
		}
	}

	if ver == "" {
		return fmt.Sprintf(">=%s", r.from)
	}

	// ">=0" can be omitted.
	// e.g. {"introduced": "0", "fixed": "1.2.3"} => "<1.2.3"
	if r.from == "0" {
		return ver
	}

	return fmt.Sprintf(">=%s, %s", r.from, ver)
}

func (r *versionRange) SetFixed(fixed string) {
	r.to = fixed
	r.toIncluded = false
}

func (r *versionRange) SetLastAffected(lastAffected string) {
	r.to = lastAffected
	r.toIncluded = true
}

type DefaultVersionRange struct {
	logger *zap.SugaredLogger
	*versionRange
}

func NewDefaultVersionRange(ecosystem Ecosystem, from string) *DefaultVersionRange {
	logger := log.Logger.With(zap.String("ECOSYSTEM", string(ecosystem)))
	return &DefaultVersionRange{logger: logger, versionRange: &versionRange{from: from}}
}

func (r *DefaultVersionRange) Contains(ver string) bool {
	c, err := version.NewConstraints(r.String())
	if err != nil {
		r.logger.Error("Failed to parse version constraint", zap.String("constraint", r.String()), zap.Error(err))
		return false
	}

	v, err := version.Parse(ver)
	if err != nil {
		r.logger.Errorw("Failed to parse version", zap.String("version", ver), zap.Error(err))
		return false
	}

	return c.Check(v)
}

type SemVerRange struct {
	logger *zap.SugaredLogger
	*versionRange
}

func NewSemVerRange(ecosystem Ecosystem, from string) *SemVerRange {
	logger := log.Logger.With(zap.String("ECOSYSTEM", string(ecosystem)))
	return &SemVerRange{logger: logger, versionRange: &versionRange{from: from}}
}

func (r *SemVerRange) Contains(ver string) bool {
	c, err := semver.NewConstraints(r.String())
	if err != nil {
		r.logger.Error("Failed to parse version constraint", zap.String("constraint", r.String()), zap.Error(err))
		return false
	}

	v, err := semver.Parse(ver)
	if err != nil {
		r.logger.Errorw("Failed to parse version", zap.String("version", ver), zap.Error(err))
		return false
	}

	return c.Check(v)
}

type NpmVersionRange struct {
	logger *zap.SugaredLogger
	*versionRange
}

func NewNpmVersionRange(from string) *NpmVersionRange {
	logger := log.Logger.With(zap.String("ECOSYSTEM", string(EcosystemNpm)))
	return &NpmVersionRange{logger: logger, versionRange: &versionRange{from: from}}
}

func (r *NpmVersionRange) Contains(ver string) bool {
	c, err := npm.NewConstraints(r.String())
	if err != nil {
		r.logger.Error("Failed to parse version constraint", zap.String("constraint", r.String()), zap.Error(err))
		return false
	}

	v, err := npm.NewVersion(ver)
	if err != nil {
		r.logger.Errorw("Failed to parse version", zap.String("version", ver), zap.Error(err))
		return false
	}

	return c.Check(v)
}

type RubyGemsVersionRange struct {
	logger *zap.SugaredLogger
	*versionRange
}

func NewRubyGemsVersionRange(from string) *RubyGemsVersionRange {
	logger := log.Logger.With(zap.String("ECOSYSTEM", string(EcosystemRubygems)))
	return &RubyGemsVersionRange{logger: logger, versionRange: &versionRange{from: from}}
}

func (r *RubyGemsVersionRange) Contains(ver string) bool {
	c, err := gem.NewConstraints(r.String())
	if err != nil {
		r.logger.Error("Failed to parse version constraint", zap.String("constraint", r.String()), zap.Error(err))
		return false
	}

	v, err := gem.NewVersion(ver)
	if err != nil {
		r.logger.Errorw("Failed to parse version", zap.String("version", ver), zap.Error(err))
		return false
	}

	return c.Check(v)
}

type PyPIVersionRange struct {
	logger *zap.SugaredLogger
	*versionRange
}

func NewPyPIVersionRange(from string) *PyPIVersionRange {
	logger := log.Logger.With(zap.String("ECOSYSTEM", string(EcosystemPyPI)))
	return &PyPIVersionRange{logger: logger, versionRange: &versionRange{from: from}}
}

func (r *PyPIVersionRange) Contains(ver string) bool {
	c, err := pep440.NewSpecifiers(r.String())
	if err != nil {
		r.logger.Errorw("Failed to parse version constraint", zap.String("constraint", r.String()), zap.Error(err))
		return false
	}

	v, err := pep440.Parse(ver)
	if err != nil {
		r.logger.Errorw("Failed to parse version", zap.String("version", ver), zap.Error(err))
		return false
	}

	return c.Check(v)
}

type MavenVersionRange struct {
	logger *zap.SugaredLogger
	*versionRange
}

func NewMavenVersionRange(from string) *MavenVersionRange {
	logger := log.Logger.With(zap.String("ECOSYSTEM", string(EcosystemMaven)))
	return &MavenVersionRange{logger: logger, versionRange: &versionRange{from: from}}
}

func (r *MavenVersionRange) Contains(ver string) bool {
	c, err := mvn.NewConstraints(r.String())
	if err != nil {
		r.logger.Errorw("Failed to parse version constraint", zap.String("constraint", r.String()), zap.Error(err))
		return false
	}

	v, err := mvn.NewVersion(ver)
	if err != nil {
		r.logger.Errorw("Failed to parse version", zap.String("version", ver), zap.Error(err))
		return false
	}

	return c.Check(v)
}
