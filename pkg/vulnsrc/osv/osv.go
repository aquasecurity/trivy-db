package osv

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/goark/go-cvss/v3/metric"
	"github.com/samber/lo"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/exp/maps"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

type Advisory struct {
	Ecosystem       types.Ecosystem
	PkgName         string
	VulnerabilityID string
	Aliases         []string

	// Advisory detail
	VulnerableVersions []string
	PatchedVersions    []string

	// Vulnerability detail
	Severity     types.Severity
	Title        string
	Description  string
	References   []string
	CVSSScoreV3  float64
	CVSSVectorV3 string
}

type OSV struct {
	dir         string
	dbc         db.Operation
	sourceID    types.SourceID
	dataSources map[types.Ecosystem]types.DataSource
	transformer Transformer
}

type Transformer interface {
	TransformAdvisories([]Advisory, Entry) ([]Advisory, error)
}

type defaultTransformer struct{}

func (t *defaultTransformer) TransformAdvisories(advs []Advisory, _ Entry) ([]Advisory, error) {
	return advs, nil
}

func New(dir string, sourceID types.SourceID, dataSources map[types.Ecosystem]types.DataSource, transformer Transformer) OSV {
	if transformer == nil {
		transformer = &defaultTransformer{}
	}
	return OSV{
		dir:         dir,
		dbc:         db.Config{},
		sourceID:    sourceID,
		dataSources: dataSources,
		transformer: transformer,
	}
}

func (o OSV) Name() types.SourceID {
	return o.sourceID
}

func (o OSV) Update(root string) error {
	rootDir := filepath.Join(root, o.dir)

	var entries []Entry
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var entry Entry
		if err := json.NewDecoder(r).Decode(&entry); err != nil {
			return xerrors.Errorf("JSON decode error (%s): %w", path, err)
		}
		entries = append(entries, entry)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("walk error: %w", err)
	}

	if err = o.save(entries); err != nil {
		return xerrors.Errorf("save error: %w", err)
	}

	return nil
}

func (o OSV) save(entries []Entry) error {
	err := o.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		for _, entry := range entries {
			if err := o.commit(tx, entry); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("batch update error: %w", err)
	}
	return nil
}

func (o OSV) commit(tx *bolt.Tx, entry Entry) error {
	if entry.Withdrawn != nil && entry.Withdrawn.Before(time.Now()) {
		return nil
	}

	// Group IDs into primary vulnerability IDs and aliases.
	vulnIDs, aliases := groupVulnIDs(entry.ID, entry.Aliases)

	references := lo.Map(entry.References, func(ref Reference, _ int) string {
		return ref.URL
	})

	// Parse []affected
	advisories, err := parseAffected(entry, vulnIDs, aliases, references)
	if err != nil {
		return xerrors.Errorf("failed to parse affected: %w", err)
	}

	// Transform advisories
	advisories, err = o.transformer.TransformAdvisories(advisories, entry)
	if err != nil {
		return xerrors.Errorf("failed to transform advisories: %w", err)
	}

	for _, adv := range advisories {
		dataSource, ok := o.dataSources[adv.Ecosystem]
		if !ok {
			continue
		}
		bktName := bucket.Name(string(adv.Ecosystem), dataSource.Name)

		if err = o.dbc.PutDataSource(tx, bktName, dataSource); err != nil {
			return xerrors.Errorf("failed to put data source: %w", err)
		}

		// Store advisories
		advisory := types.Advisory{
			VendorIDs:          adv.Aliases,
			VulnerableVersions: adv.VulnerableVersions,
			PatchedVersions:    adv.PatchedVersions,
		}
		if err = o.dbc.PutAdvisoryDetail(tx, adv.VulnerabilityID, adv.PkgName, []string{bktName}, advisory); err != nil {
			return xerrors.Errorf("failed to save OSV advisory: %w", err)
		}

		// Store vulnerability details
		vuln := types.VulnerabilityDetail{
			Severity:     adv.Severity,
			References:   adv.References,
			Title:        adv.Title,
			Description:  adv.Description,
			CvssScoreV3:  adv.CVSSScoreV3,
			CvssVectorV3: adv.CVSSVectorV3,
		}

		if err = o.dbc.PutVulnerabilityDetail(tx, adv.VulnerabilityID, o.sourceID, vuln); err != nil {
			return xerrors.Errorf("failed to put vulnerability detail (%s): %w", adv.VulnerabilityID, err)
		}

		if err = o.dbc.PutVulnerabilityID(tx, adv.VulnerabilityID); err != nil {
			return xerrors.Errorf("failed to put vulnerability id (%s): %w", adv.VulnerabilityID, err)
		}
	}
	return nil
}

func groupVulnIDs(id string, aliases []string) ([]string, []string) {
	var cveIDs, nonCVEIDs []string
	for _, a := range append(aliases, id) {
		if strings.HasPrefix(a, "CVE-") {
			cveIDs = append(cveIDs, a)
		} else {
			nonCVEIDs = append(nonCVEIDs, a)
		}
	}
	if len(cveIDs) == 0 {
		// Use the original vulnerability ID
		// e.g. PYSEC-2021-335 and GHSA-wjx8-cgrm-hh8p
		return []string{id}, aliases
	}
	return cveIDs, nonCVEIDs
}

// parseAffected parses the affected fields
// cf. https://ossf.github.io/osv-schema/#affected-fields
func parseAffected(entry Entry, vulnIDs, aliases, references []string) ([]Advisory, error) {
	// Severities can be found both in severity and affected[].severity fields.
	cvssVectorV3, cvssScoreV3, err := parseSeverity(entry.Severities)
	if err != nil {
		return nil, xerrors.Errorf("failed to decode CVSSv3 vector: %w", err)
	}

	uniqAdvisories := map[string]Advisory{}
	for _, affected := range entry.Affected {
		ecosystem := convertEcosystem(affected.Package.Ecosystem)
		if ecosystem == vulnerability.Unknown {
			continue
		}
		pkgName := vulnerability.NormalizePkgName(ecosystem, affected.Package.Name)

		vulnerableVersions, patchedVersions, err := parseAffectedVersions(affected)
		if err != nil {
			return nil, xerrors.Errorf("failed to parse affected: %w", err)
		}

		// Parse affected[].severity
		if vecV3, scoreV3, err := parseSeverity(affected.Severities); err != nil {
			return nil, xerrors.Errorf("failed to decode CVSSv3 vector: %w", err)
		} else if vecV3 != "" {
			// Overwrite the CVSS vector and score if affected[].severity is set
			cvssVectorV3, cvssScoreV3 = vecV3, scoreV3
		}

		key := fmt.Sprintf("%s/%s", ecosystem, pkgName)
		for _, vulnID := range vulnIDs {
			if adv, ok := uniqAdvisories[key]; ok {
				// The same package could be repeated with different version ranges.
				// cf. https://github.com/github/advisory-database/blob/0996f81ca6f1b65ba25f8e71fba263cb1e54ced5/advisories/github-reviewed/2019/12/GHSA-wjx8-cgrm-hh8p/GHSA-wjx8-cgrm-hh8p.json
				adv.VulnerableVersions = append(adv.VulnerableVersions, vulnerableVersions...)
				adv.PatchedVersions = append(adv.PatchedVersions, patchedVersions...)
				uniqAdvisories[key] = adv
			} else {
				uniqAdvisories[key] = Advisory{
					Ecosystem:          ecosystem,
					PkgName:            pkgName,
					VulnerabilityID:    vulnID,
					Aliases:            aliases,
					VulnerableVersions: vulnerableVersions,
					PatchedVersions:    patchedVersions,
					Title:              entry.Summary,
					Description:        entry.Details,
					References:         references,
					CVSSVectorV3:       cvssVectorV3,
					CVSSScoreV3:        cvssScoreV3,
				}
			}
		}
	}
	return maps.Values(uniqAdvisories), nil
}

// parseAffectedVersions parses the affected.versions and affected.ranges fields
// cf.
// - https://ossf.github.io/osv-schema/#affectedversions-field
// - https://ossf.github.io/osv-schema/#affectedranges-field
func parseAffectedVersions(affected Affected) ([]string, []string, error) {
	var patchedVersions, vulnerableVersions []string
	for _, affects := range affected.Ranges {
		if affects.Type == RangeTypeGit {
			continue
		}

		var vulnerable string
		for _, event := range affects.Events {
			switch {
			case event.Introduced != "":
				// e.g. {"introduced": "1.2.0}, {"introduced": "2.2.0}
				if vulnerable != "" {
					vulnerableVersions = append(vulnerableVersions, vulnerable)
				}
				vulnerable = fmt.Sprintf(">=%s", event.Introduced)
			case event.Fixed != "":
				// patched versions
				patchedVersions = append(patchedVersions, event.Fixed)

				// e.g. {"introduced": "1.2.0}, {"fixed": "1.2.5}
				vulnerable = fmt.Sprintf("%s, <%s", vulnerable, event.Fixed)
			case event.LastAffected != "":
				vulnerable = fmt.Sprintf("%s, <=%s", vulnerable, event.LastAffected)
			}
		}
		if vulnerable != "" {
			vulnerableVersions = append(vulnerableVersions, vulnerable)
		}
	}

	// Alternatively, use affected.Versions if affected.Ranges is empty.
	if len(affected.Ranges) == 0 {
		for _, v := range affected.Versions {
			vulnerableVersions = append(vulnerableVersions, fmt.Sprintf("=%s", v))
		}
	}

	return vulnerableVersions, patchedVersions, nil
}

// parseSeverity parses the severity field and returns CVSSv3 vector and score
// cf.
// - https://ossf.github.io/osv-schema/#severity-field
// - https://ossf.github.io/osv-schema/#affectedseverity-field
func parseSeverity(severities []Severity) (string, float64, error) {
	for _, s := range severities {
		if s.Type == "CVSS_V3" {
			// CVSS vectors possibly have `/` suffix
			// e.g. https://github.com/github/advisory-database/blob/2d3bc73d2117893b217233aeb95b9236c7b93761/advisories/github-reviewed/2019/05/GHSA-j59f-6m4q-62h6/GHSA-j59f-6m4q-62h6.json#L14
			// Trim the suffix to avoid errors
			cvssVectorV3 := strings.TrimSuffix(s.Score, "/")
			metrics, err := metric.NewTemporal().Decode(cvssVectorV3)
			if err != nil {
				return "", 0, xerrors.Errorf("failed to decode CVSSv3 vector: %w", err)
			}
			cvssScoreV3 := metrics.Score()
			return cvssVectorV3, cvssScoreV3, nil
		}
	}
	return "", 0, nil
}

func convertEcosystem(eco Ecosystem) types.Ecosystem {
	// cf. https://ossf.github.io/osv-schema/#affectedpackage-field
	switch strings.ToLower(string(eco)) {
	case "go":
		return vulnerability.Go
	case "npm":
		return vulnerability.Npm
	case "pypi":
		return vulnerability.Pip
	case "rubygems":
		return vulnerability.RubyGems
	case "crates.io":
		return vulnerability.Cargo
	case "packagist":
		return vulnerability.Composer
	case "maven":
		return vulnerability.Maven
	case "nuget":
		return vulnerability.NuGet
	case "hex":
		return vulnerability.Erlang
	case "pub":
		return vulnerability.Pub
	case "swifturl", "purl-type:swift":
		// GHSA still uses "purl-type:swift" for Swift advisories.
		// cf. https://github.com/github/advisory-database/blob/db1cdfb553e48f18aa27d7e929d200563451391a/advisories/github-reviewed/2023/07/GHSA-jq43-q8mx-r7mq/GHSA-jq43-q8mx-r7mq.json#L20
		return vulnerability.Swift
	case "bitnami":
		return vulnerability.Bitnami
	default:
		return vulnerability.Unknown
	}
}
