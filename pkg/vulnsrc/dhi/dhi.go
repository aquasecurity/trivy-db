// Package dhi ingests Docker Hardened Images advisories in OSV format.
package dhi

import (
	"path/filepath"
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"github.com/samber/oops"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/osv"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const osvEcosystem = "Docker Hardened Images"

var dhiDir = filepath.Join("vuln-list", "dhi")

var dataSource = types.DataSource{
	ID:   vulnerability.DHI,
	Name: "Docker Hardened Images Advisories",
	URL:  "https://github.com/docker-hardened-images/advisories",
}

// lineagePURLTypes maps each supported DHI lineage to the PURL type of its packages.
var lineagePURLTypes = map[string]string{
	"alpine": packageurl.TypeApk,
	"debian": packageurl.TypeDebian,
}

// NewVulnSrc returns the DHI OSV vulnerability source.
func NewVulnSrc() osv.OSV {
	return osv.New(dhiDir, vulnerability.DHI, map[ecosystem.Type]types.DataSource{
		ecosystem.DHI: dataSource,
	}, osv.WithBucketResolver(strings.ToLower(osvEcosystem), resolveBucket), osv.WithTransformer(&transformer{logger: log.WithPrefix("dhi")}), osv.WithEntryIDAsPrimary())
}

// resolveBucket returns the release-scoped bucket for an ecosystem suffix such as "alpine:3.24".
// Resolving the release here, before affected entries are aggregated, keeps entries for the
// same package in different releases from being merged into one advisory.
func resolveBucket(suffix string) (bucket.Bucket, error) {
	lineage, release, err := parseEcosystemSuffix(suffix)
	if err != nil {
		return nil, err
	}
	return bucket.NewDHI(lineage, release, dataSource), nil
}

// parseEcosystemSuffix splits and validates the "<lineage>:<release>" part of a DHI ecosystem.
func parseEcosystemSuffix(suffix string) (string, string, error) {
	lineage, release, _ := strings.Cut(strings.ToLower(suffix), ":")
	if _, ok := lineagePURLTypes[lineage]; !ok || !validRelease(release) {
		return "", "", oops.With("ecosystem_suffix", suffix).Errorf("DHI ecosystem must be %s:<Alpine|Debian>:<major>[.<minor>]", osvEcosystem)
	}
	return lineage, release, nil
}

// validRelease reports whether a release is a numeric major or major.minor version.
func validRelease(release string) bool {
	parts := strings.Split(release, ".")
	if len(parts) > 2 {
		return false
	}
	for _, part := range parts {
		if part == "" || strings.Trim(part, "0123456789") != "" {
			return false
		}
	}
	return true
}

// identity is the release-scoped package identity of one affected entry.
type identity struct {
	lineage, release, arch string
}

// parseIdentity validates an affected entry. The ecosystem is the source of truth for the
// lineage and release. The os_name, os_distro and os_version PURL qualifiers are optional,
// but any that are present must agree with it. Names are compared case-insensitively, as
// the OSV parser does when it resolves the bucket.
func parseIdentity(affected osv.Affected) (identity, error) {
	eco, suffix, _ := strings.Cut(affected.Package.Ecosystem, ":")
	if !strings.EqualFold(eco, osvEcosystem) {
		return identity{}, oops.With("ecosystem", affected.Package.Ecosystem).Errorf("unsupported DHI ecosystem")
	}
	lineage, release, err := parseEcosystemSuffix(suffix)
	if err != nil {
		return identity{}, err
	}

	p, err := packageurl.FromString(affected.Package.PURL)
	if err != nil {
		return identity{}, oops.With("purl", affected.Package.PURL).Wrapf(err, "failed to parse DHI package PURL")
	}
	if !strings.EqualFold(p.Namespace, ecosystem.DHI.String()) || p.Type != lineagePURLTypes[lineage] {
		return identity{}, oops.With("purl", affected.Package.PURL).With("lineage", lineage).Errorf("DHI package PURL does not match the ecosystem lineage")
	}
	for key, want := range map[string]string{"os_name": ecosystem.DHI.String(), "os_distro": lineage, "os_version": release} {
		if got, ok := p.Qualifiers.Map()[key]; ok && !strings.EqualFold(got, want) {
			return identity{}, oops.With("purl", affected.Package.PURL).With("qualifier", key).Errorf("DHI package PURL qualifier does not match the ecosystem")
		}
	}
	return identity{lineage: lineage, release: release, arch: p.Qualifiers.Map()["arch"]}, nil
}

type transformer struct {
	logger *log.Logger
}

// PostParseAffected sets the architecture the advisory applies to from the package PURL.
// Malformed entries are left unchanged here and dropped by TransformAdvisories.
func (*transformer) PostParseAffected(adv osv.Advisory, affected osv.Affected) (osv.Advisory, error) {
	id, err := parseIdentity(affected)
	if err != nil {
		return adv, nil
	}
	// Entries aggregated into one advisory share the same architecture, or are dropped
	// by TransformAdvisories, so the last entry's architecture holds for all of them.
	if id.arch != "" {
		adv.Arches = []string{id.arch}
	}
	return adv, nil
}

// TransformAdvisories drops the advisories of packages with a malformed affected entry, and
// of packages whose affected entries in one release have different architectures, since an
// aggregated advisory holds a single architecture set. Dropped packages are logged rather
// than failing the build, so one bad DHI affected entry cannot block the whole database.
func (t *transformer) TransformAdvisories(advs []osv.Advisory, entry osv.Entry) ([]osv.Advisory, error) {
	arches := make(map[string]string)
	skip := make(map[string]bool)
	for _, affected := range entry.Affected {
		_, suffix, _ := strings.Cut(affected.Package.Ecosystem, ":")
		bkt, err := resolveBucket(suffix)
		if err != nil {
			// The OSV parser has already skipped this entry, as its bucket cannot be resolved.
			t.logger.Warn("Skipping DHI affected entry", "id", entry.ID, "ecosystem", affected.Package.Ecosystem, "err", err.Error())
			continue
		}
		key := bkt.Name() + "/" + vulnerability.NormalizePkgName(ecosystem.DHI, affected.Package.Name)

		id, err := parseIdentity(affected)
		if err != nil {
			t.logger.Warn("Skipping DHI package with a malformed affected entry", "id", entry.ID, "package", key, "err", err.Error())
			skip[key] = true
			continue
		}
		if arch, ok := arches[key]; ok && arch != id.arch {
			t.logger.Warn("Skipping DHI package with affected entries for different architectures", "id", entry.ID, "package", key)
			skip[key] = true
		}
		arches[key] = id.arch
	}
	return lo.Reject(advs, func(adv osv.Advisory, _ int) bool {
		return skip[adv.Bucket.Name()+"/"+adv.PkgName]
	}), nil
}
