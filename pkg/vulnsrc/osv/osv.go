package osv

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	"github.com/samber/lo"
	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

type Advisory struct {
	Bucket          bucket.Bucket
	PkgName         string
	VulnerabilityID string
	Aliases         []string

	// Advisory detail
	VulnerableVersions []string
	PatchedVersions    []string
	OSes               []string
	Arches             []string

	// Vulnerability detail
	Severity     types.Severity
	Title        string
	Description  string
	References   []string
	CVSSScoreV3  float64
	CVSSVectorV3 string
	Modified     time.Time
	Published    time.Time
}

type OSV struct {
	dir         string
	dbc         db.Operation
	sourceID    types.SourceID
	dataSources map[ecosystem.Type]types.DataSource
	transformer Transformer
}

type Transformer interface {
	// PostParseAffected is called after parseAffected to transform Advisory with Affected
	PostParseAffected(Advisory, Affected) (Advisory, error)

	// TransformAdvisories transforms the advisories
	TransformAdvisories([]Advisory, Entry) ([]Advisory, error)
}

type defaultTransformer struct{}

func (t *defaultTransformer) PostParseAffected(adv Advisory, _ Affected) (Advisory, error) {
	return adv, nil
}

func (t *defaultTransformer) TransformAdvisories(advs []Advisory, _ Entry) ([]Advisory, error) {
	return advs, nil
}

func New(dir string, sourceID types.SourceID, dataSources map[ecosystem.Type]types.DataSource, transformer Transformer) OSV {
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
	eb := oops.In(string(o.sourceID)).With("root_dir", rootDir)

	var entries []Entry
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		if filepath.Ext(path) != ".json" {
			return nil
		}
		var entry Entry
		if err := json.NewDecoder(r).Decode(&entry); err != nil {
			return oops.With("file_path", path).Wrapf(err, "json decode error")
		}
		entries = append(entries, entry)
		return nil
	})
	if err != nil {
		return eb.Wrapf(err, "walk error")
	}

	if err = o.save(entries); err != nil {
		return eb.Wrapf(err, "save error")
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
		return oops.Wrapf(err, "batch update error")
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
	advisories, err := o.parseAffected(entry, vulnIDs, aliases, references)
	if err != nil {
		return oops.Wrapf(err, "failed to parse affected")
	}

	// Transform advisories
	advisories, err = o.transformer.TransformAdvisories(advisories, entry)
	if err != nil {
		return oops.Wrapf(err, "failed to transform advisories")
	}

	for _, adv := range advisories {
		// Skip advisories with nil bucket
		if lo.IsNil(adv.Bucket) {
			continue
		}

		bktName := adv.Bucket.Name()
		dsb, ok := adv.Bucket.(bucket.DataSourceBucket)
		if !ok {
			return oops.With("bucket_name", bktName).With("bucket_type", fmt.Sprintf("%T", adv.Bucket)).Errorf("bucket does not implement DataSourceBucket interface")
		}
		if err = o.dbc.PutDataSource(tx, bktName, dsb.DataSource()); err != nil {
			return oops.Wrapf(err, "failed to put data source")
		}

		// Store advisories
		advisory := types.Advisory{
			VendorIDs:          adv.Aliases,
			VulnerableVersions: adv.VulnerableVersions,
			PatchedVersions:    adv.PatchedVersions,
			OSes:               adv.OSes,
			Arches:             adv.Arches,
		}
		if err = o.dbc.PutAdvisoryDetail(tx, adv.VulnerabilityID, adv.PkgName, []string{bktName}, advisory); err != nil {
			return oops.Wrapf(err, "failed to save advisory")
		}

		// Store vulnerability details
		vuln := types.VulnerabilityDetail{
			Severity:         adv.Severity,
			References:       adv.References,
			Title:            adv.Title,
			Description:      adv.Description,
			CvssScoreV3:      adv.CVSSScoreV3,
			CvssVectorV3:     adv.CVSSVectorV3,
			PublishedDate:    lo.Ternary(!adv.Published.IsZero(), &adv.Published, nil),
			LastModifiedDate: lo.Ternary(!adv.Modified.IsZero(), &adv.Modified, nil),
		}

		if err = o.dbc.PutVulnerabilityDetail(tx, adv.VulnerabilityID, o.sourceID, vuln); err != nil {
			return oops.Wrapf(err, "failed to put vulnerability detail")
		}

		if err = o.dbc.PutVulnerabilityID(tx, adv.VulnerabilityID); err != nil {
			return oops.Wrapf(err, "failed to put vulnerability id")
		}
	}
	return nil
}

// parseAffected parses the affected fields
// cf. https://ossf.github.io/osv-schema/#affected-fields
func (o OSV) parseAffected(entry Entry, vulnIDs, aliases, references []string) ([]Advisory, error) {
	eb := oops.With("entry_id", entry.ID).With("vuln_ids", vulnIDs).With("aliases", aliases)

	// Severities can be found both in severity and affected[].severity fields.
	cvssVectorV3, cvssScoreV3, err := parseSeverity(entry.Severities)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to decode CVSS vector")
	}

	uniqAdvisories := map[string]Advisory{}
	for _, affected := range entry.Affected {
		bkt, err := o.convertEcosystem(affected.Package.Ecosystem)
		if err != nil {
			// Skip unsupported ecosystems
			continue
		}
		pkgName := vulnerability.NormalizePkgName(bkt.Ecosystem(), affected.Package.Name)
		eb := eb.With("ecosystem", bkt.Ecosystem()).With("package_name", pkgName)

		vulnerableVersions, patchedVersions, err := parseAffectedVersions(affected)
		if err != nil {
			return nil, eb.Wrapf(err, "failed to parse affected")
		}

		// Parse affected[].severity
		if vecV3, scoreV3, err := parseSeverity(affected.Severities); err != nil {
			return nil, eb.Wrapf(err, "failed to decode CVSS vector")
		} else if vecV3 != "" {
			// Overwrite the CVSS vector and score if affected[].severity is set
			cvssVectorV3, cvssScoreV3 = vecV3, scoreV3
		}

		key := fmt.Sprintf("%s/%s", bkt.Ecosystem(), pkgName)
		for _, vulnID := range vulnIDs {
			adv, ok := uniqAdvisories[key]
			if ok {
				// The same package could be repeated with different version ranges.
				// cf. https://github.com/github/advisory-database/blob/0996f81ca6f1b65ba25f8e71fba263cb1e54ced5/advisories/github-reviewed/2019/12/GHSA-wjx8-cgrm-hh8p/GHSA-wjx8-cgrm-hh8p.json
				adv.VulnerableVersions = append(adv.VulnerableVersions, vulnerableVersions...)
				adv.PatchedVersions = append(adv.PatchedVersions, patchedVersions...)
			} else {
				adv = Advisory{
					Bucket:             bkt,
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
					Modified:           entry.Modified,
					Published:          entry.Published,
				}
			}

			// Call PostParseAffected hook
			adv, err = o.transformer.PostParseAffected(adv, affected)
			if err != nil {
				return nil, eb.Wrapf(err, "failed to post process affected")
			}
			uniqAdvisories[key] = adv
		}
	}
	return lo.Values(uniqAdvisories), nil
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

// parseAffectedVersions parses the affected.versions and affected.ranges fields
// cf.
// - https://ossf.github.io/osv-schema/#affectedversions-field
// - https://ossf.github.io/osv-schema/#affectedranges-field
func parseAffectedVersions(affected Affected) ([]string, []string, error) {
	var patchedVersions, vulnerableVersions []string
	var affectedRanges []VersionRange
	for _, affects := range affected.Ranges {
		if affects.Type == RangeTypeGit {
			continue
		}

		var index int
		for _, event := range affects.Events {
			switch {
			// Each "introduced" event implies a new version range
			// e.g. {"introduced": "1.2.0"}, {"introduced": "2.2.0"}
			case event.Introduced != "":
				affectedRanges = append(affectedRanges, NewVersionRange(affected.Package.Ecosystem, event.Introduced))
				index = len(affectedRanges) - 1
			// e.g. {"introduced": "1.2.0"}, {"fixed": "1.2.5"}
			case event.Fixed != "":
				affectedRanges[index].SetFixed(event.Fixed)
				patchedVersions = append(patchedVersions, event.Fixed)
			// e.g. {"introduced": "1.2.0"}, {"last_affected": "1.2.5"}
			case event.LastAffected != "":
				affectedRanges[index].SetLastAffected(event.LastAffected)
			}
		}
	}

	for _, r := range affectedRanges {
		vulnerableVersions = append(vulnerableVersions, r.String())
	}

	for _, v := range affected.Versions {
		// We don't need to add the versions that are already included in the ranges
		ok, err := versionContains(affectedRanges, v)
		if err != nil {
			log.WithPrefix("osv").Error("Version comparison error",
				log.String("ecosystem", affected.Package.Ecosystem),
				log.String("package", affected.Package.Name),
				log.Err(err),
			)
		}
		if !ok {
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
		if s.Type == "CVSS_V3" && s.Score != "" {
			// CVSS vectors possibly have `/` suffix
			// e.g. https://github.com/github/advisory-database/blob/2d3bc73d2117893b217233aeb95b9236c7b93761/advisories/github-reviewed/2019/05/GHSA-j59f-6m4q-62h6/GHSA-j59f-6m4q-62h6.json#L14
			// Trim the suffix to avoid errors
			cvssVectorV3 := strings.TrimSuffix(s.Score, "/")
			eb := oops.With("cvss_vector_v3", cvssVectorV3)
			switch {
			case strings.HasPrefix(cvssVectorV3, "CVSS:3.0"):
				cvss, err := gocvss30.ParseVector(cvssVectorV3)
				if err != nil {
					return "", 0, eb.Wrapf(err, "failed to parse CVSSv3.0 vector")
				}
				// cvss.EnvironmentalScore() returns the optimal score required from Vector.
				// If the Environmental Metrics is not set, it will be the same value as TemporalScore(),
				// and if Temporal Metrics is not set, it will be the same value as Basescore().
				return cvssVectorV3, cvss.EnvironmentalScore(), nil
			case strings.HasPrefix(s.Score, "CVSS:3.1"):
				cvss, err := gocvss31.ParseVector(cvssVectorV3)
				if err != nil {
					return "", 0, oops.Wrapf(err, "failed to parse CVSSv3.1 vector")
				}
				// cvss.EnvironmentalScore() returns the optimal score required from Vector.
				// If the Environmental Metrics is not set, it will be the same value as TemporalScore(),
				// and if Temporal Metrics is not set, it will be the same value as Basescore().
				return cvssVectorV3, cvss.EnvironmentalScore(), nil
			default:
				return "", 0, eb.Errorf("vector does not have CVSS v3 prefix: \"CVSS:3.0\" or \"CVSS:3.1\"")
			}
		}
	}
	return "", 0, nil
}

func (o OSV) convertEcosystem(raw string) (bucket.Bucket, error) {
	eco, _, _ := strings.Cut(raw, ":")
	switch strings.ToLower(eco) {
	case ecosystemGo:
		return bucket.NewGo(o.dataSources[ecosystem.Go])
	case ecosystemNpm:
		return bucket.NewNpm(o.dataSources[ecosystem.Npm])
	case ecosystemPyPI:
		return bucket.NewPyPI(o.dataSources[ecosystem.Pip])
	case ecosystemRubygems:
		return bucket.NewRubyGems(o.dataSources[ecosystem.RubyGems])
	case ecosystemCrates:
		return bucket.NewCargo(o.dataSources[ecosystem.Cargo])
	case ecosystemPackagist:
		return bucket.NewComposer(o.dataSources[ecosystem.Composer])
	case ecosystemMaven:
		return bucket.NewMaven(o.dataSources[ecosystem.Maven])
	case ecosystemNuGet:
		return bucket.NewNuGet(o.dataSources[ecosystem.NuGet])
	case ecosystemHex:
		return bucket.NewErlang(o.dataSources[ecosystem.Erlang])
	case ecosystemPub:
		return bucket.NewPub(o.dataSources[ecosystem.Pub])
	case ecosystemSwiftURL:
		return bucket.NewSwift(o.dataSources[ecosystem.Swift])
	case ecosystemBitnami:
		return bucket.NewBitnami(o.dataSources[ecosystem.Bitnami])
	case ecosystemKubernetes:
		return bucket.NewKubernetes(o.dataSources[ecosystem.Kubernetes])
	default:
		return nil, oops.Errorf("unsupported ecosystem: %s", eco)
	}
}

func versionContains(ranges []VersionRange, version string) (bool, error) {
	for _, r := range ranges {
		if ok, err := r.Contains(version); err != nil {
			return false, err
		} else if ok {
			return true, nil
		}
	}
	return false, nil
}
