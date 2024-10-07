package osv

import (
	"fmt"

	mvn "github.com/masahiro331/go-mvn-version"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-gem-version"
	"github.com/aquasecurity/go-npm-version/pkg"
	pep440 "github.com/aquasecurity/go-pep440-version"
	"github.com/aquasecurity/go-version/pkg/semver"
	"github.com/aquasecurity/go-version/pkg/version"
)

type VersionRange interface {
	Contains(ver string) (bool, error)
	String() string
	SetFixed(fixed string)
	SetLastAffected(lastAffected string)
}

func NewVersionRange(ecosystem Ecosystem, from string) VersionRange {
	vr := &versionRange{from: from}
	switch ecosystem {
	case EcosystemNpm:
		return &NpmVersionRange{versionRange: vr}
	case EcosystemRubygems:
		return &RubyGemsVersionRange{versionRange: vr}
	case EcosystemPyPI:
		return &PyPIVersionRange{versionRange: vr}
	case EcosystemMaven:
		return &MavenVersionRange{versionRange: vr}
	case EcosystemGo, EcosystemCrates, EcosystemNuGet:
		return &SemVerRange{versionRange: vr}
	case EcosystemPackagist:
		return &DefaultVersionRange{versionRange: vr}
	default:
		return &DefaultVersionRange{versionRange: vr}
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
	*versionRange
}

func (r *DefaultVersionRange) Contains(ver string) (bool, error) {
	c, err := version.NewConstraints(r.String())
	if err != nil {
		return false, xerrors.Errorf("failed to parse version constraint: %w", err)
	}

	v, err := version.Parse(ver)
	if err != nil {
		return false, xerrors.Errorf("failed to parse version: %w", err)
	}

	return c.Check(v), nil
}

type SemVerRange struct {
	*versionRange
}

func (r *SemVerRange) Contains(ver string) (bool, error) {
	c, err := semver.NewConstraints(r.String())
	if err != nil {
		return false, xerrors.Errorf("failed to parse version constraint: %w", err)
	}

	v, err := semver.Parse(ver)
	if err != nil {
		return false, xerrors.Errorf("failed to parse version: %w", err)
	}

	return c.Check(v), nil
}

type NpmVersionRange struct {
	*versionRange
}

func (r *NpmVersionRange) Contains(ver string) (bool, error) {
	c, err := npm.NewConstraints(r.String())
	if err != nil {
		return false, xerrors.Errorf("failed to parse version constraint: %w", err)
	}

	v, err := npm.NewVersion(ver)
	if err != nil {
		return false, xerrors.Errorf("failed to parse version: %w", err)
	}

	return c.Check(v), nil
}

type RubyGemsVersionRange struct {
	*versionRange
}

func (r *RubyGemsVersionRange) Contains(ver string) (bool, error) {
	c, err := gem.NewConstraints(r.String())
	if err != nil {
		return false, xerrors.Errorf("failed to parse version constraint: %w", err)
	}

	v, err := gem.NewVersion(ver)
	if err != nil {
		return false, xerrors.Errorf("failed to parse version: %w", err)
	}

	return c.Check(v), nil
}

type PyPIVersionRange struct {
	*versionRange
}

func (r *PyPIVersionRange) Contains(ver string) (bool, error) {
	c, err := pep440.NewSpecifiers(r.String())
	if err != nil {
		return false, xerrors.Errorf("failed to parse version constraint: %w", err)
	}

	v, err := pep440.Parse(ver)
	if err != nil {
		return false, xerrors.Errorf("failed to parse version: %w", err)
	}

	return c.Check(v), nil
}

type MavenVersionRange struct {
	*versionRange
}

func (r *MavenVersionRange) Contains(ver string) (bool, error) {
	c, err := mvn.NewConstraints(r.String())
	if err != nil {
		return false, xerrors.Errorf("failed to parse version constraint: %w", err)
	}

	v, err := mvn.NewVersion(ver)
	if err != nil {
		return false, xerrors.Errorf("failed to parse version: %w", err)
	}

	return c.Check(v), nil
}
