package rocky

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/samber/lo"
	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	rockyDir       = "rocky"
	platformFormat = "rocky %s"
)

var (
	targetRepos = []string{
		"BaseOS",
		"AppStream",
		"extras",
	}
	targetArches = []string{
		"x86_64",
		"aarch64",
	}
	source = types.DataSource{
		ID:   vulnerability.Rocky,
		Name: "Rocky Linux updateinfo",
		URL:  "https://download.rockylinux.org/pub/rocky/",
	}
)

type PutInput struct {
	PlatformName string
	CveID        string
	Vuln         types.VulnerabilityDetail
	Advisories   map[string]types.Advisories // pkg name => advisory
	Erratum      RLSA                        // for extensibility, not used in trivy-db
}

type DB interface {
	db.Operation
	db.Getter
	Put(*bolt.Tx, PutInput) error
}

type VulnSrc struct {
	DB
	logger *log.Logger
}

type Rocky struct {
	db.Operation
}

func NewVulnSrc() *VulnSrc {
	return &VulnSrc{
		DB:     &Rocky{Operation: db.Config{}},
		logger: log.WithPrefix("rocky"),
	}
}

func (vs *VulnSrc) Name() types.SourceID {
	return source.ID
}

func (vs *VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", rockyDir)
	eb := oops.In("rocky").With("root_dir", rootDir)

	errata, err := vs.parse(rootDir)
	if err != nil {
		return eb.Wrapf(err, "parse error")
	}
	if err = vs.put(errata); err != nil {
		return eb.Wrapf(err, "save error")
	}

	return nil
}

// parse parses all the advisories from Rocky Linux.
// It is exported for those who want to customize trivy-db.
func (vs *VulnSrc) parse(rootDir string) (map[string][]RLSA, error) {
	errata := map[string][]RLSA{}
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		eb := oops.With("file_path", path)

		var erratum RLSA
		if err := json.NewDecoder(r).Decode(&erratum); err != nil {
			return eb.Wrapf(err, "json decode error")
		}

		dirs := strings.Split(strings.TrimPrefix(path, rootDir), string(filepath.Separator))[1:]
		if len(dirs) != 5 {
			vs.logger.Warn("Invalid path", log.FilePath(path))
			return nil
		}

		// vulnerabilities are contained in directories with a minor version(like 8.5)
		majorVer := dirs[0]
		if idx := strings.Index(dirs[0], "."); idx != -1 {
			majorVer = dirs[0][:idx]
		}
		repo, arch := dirs[1], dirs[2]
		if !slices.Contains(targetRepos, repo) {
			vs.logger.Warn("Unsupported Rocky repo", log.String("repo", repo))
			return nil
		}

		if !slices.Contains(targetArches, arch) {
			vs.logger.Warn("Unsupported Rocky arch", log.String("arch", arch))
			return nil
		}

		errata[majorVer] = append(errata[majorVer], erratum)
		return nil
	})
	if err != nil {
		return nil, oops.Wrapf(err, "walk error")
	}
	return errata, nil
}

func (vs *VulnSrc) put(errataVer map[string][]RLSA) error {
	err := vs.BatchUpdate(func(tx *bolt.Tx) error {
		for majorVer, errata := range errataVer {
			platformName := fmt.Sprintf(platformFormat, majorVer)
			eb := oops.With("major_version", majorVer)
			if err := vs.PutDataSource(tx, platformName, source); err != nil {
				return eb.Wrapf(err, "failed to put data source")
			}
			if err := vs.commit(tx, platformName, errata); err != nil {
				return eb.Wrapf(err, "save error")
			}
		}
		return nil
	})
	if err != nil {
		return oops.Wrapf(err, "batch update error")
	}
	return nil
}

func (vs *VulnSrc) commit(tx *bolt.Tx, platformName string, errata []RLSA) error {
	savedInputs := map[string]PutInput{}
	for _, erratum := range errata {
		for _, cveID := range erratum.CveIDs {
			input := PutInput{
				Advisories: map[string]types.Advisories{},
			}
			if in, ok := savedInputs[cveID]; ok {
				input = in
			}
			for _, pkg := range erratum.Packages {
				// Skip the modular packages until the following bug is fixed.
				// https://forums.rockylinux.org/t/some-errata-missing-in-comparison-with-rhel-and-almalinux/3843/8
				if strings.Contains(pkg.Release, ".module+el") {
					continue
				}

				entry := types.Advisory{
					FixedVersion: utils.ConstructVersion(pkg.Epoch, pkg.Version, pkg.Release),
					Arches:       []string{pkg.Arch},
					VendorIDs:    []string{erratum.ID},
				}

				// if the advisory for this package and CVE have been kept - just add the new architecture
				if adv, ok := input.Advisories[pkg.Name]; ok {
					// update `fixedVersion` if `fixedVersion` for `x86_64` was not previously saved
					adv.FixedVersion = fixedVersion(adv.FixedVersion, entry.FixedVersion, pkg.Arch)

					old, i, found := lo.FindIndexOf(adv.Entries, func(adv types.Advisory) bool {
						return adv.FixedVersion == entry.FixedVersion
					})

					// If the advisory with the same fixed version and RLSA-ID is present - just add the new architecture
					if found {
						if !slices.Contains(old.Arches, pkg.Arch) {
							adv.Entries[i].Arches = append(old.Arches, pkg.Arch)
						}
						if !slices.Contains(old.VendorIDs, erratum.ID) {
							adv.Entries[i].VendorIDs = append(old.VendorIDs, erratum.ID)
						}
						input.Advisories[pkg.Name] = adv
					} else if !found {
						adv.Entries = append(adv.Entries, entry)
						input.Advisories[pkg.Name] = adv
					}
				} else {
					input.Advisories[pkg.Name] = types.Advisories{
						// will save `0.0.0` version for non-`x86_64` arch
						// to avoid false positives when using old Trivy with new database
						FixedVersion: fixedVersion("0.0.0", entry.FixedVersion, pkg.Arch), // For backward compatibility
						Entries:      []types.Advisory{entry},
					}
				}
			}

			if len(input.Advisories) == 0 {
				continue
			}

			var references []string
			for _, ref := range erratum.References {
				references = append(references, ref.Href)
			}

			vuln := types.VulnerabilityDetail{
				Severity:    generalizeSeverity(erratum.Severity),
				References:  references,
				Title:       erratum.Title,
				Description: erratum.Description,
			}

			input.PlatformName = platformName
			input.CveID = cveID
			input.Vuln = vuln
			input.Erratum = erratum // For Trivy Premium

			savedInputs[cveID] = input
		}
	}

	for _, input := range savedInputs {
		err := vs.Put(tx, input)
		if err != nil {
			return oops.Wrapf(err, "db put error")
		}
	}
	return nil
}

func (r *Rocky) Put(tx *bolt.Tx, input PutInput) error {
	if err := r.PutVulnerabilityDetail(tx, input.CveID, source.ID, input.Vuln); err != nil {
		return oops.Wrapf(err, "failed to save vulnerability detail")
	}

	// for optimization
	if err := r.PutVulnerabilityID(tx, input.CveID); err != nil {
		return oops.Wrapf(err, "failed to save vulnerability ID")
	}

	for pkgName, advisory := range input.Advisories {
		for _, entry := range advisory.Entries {
			sort.Strings(entry.Arches)
			sort.Strings(entry.VendorIDs)
		}
		if err := r.PutAdvisoryDetail(tx, input.CveID, pkgName, []string{input.PlatformName}, advisory); err != nil {
			return oops.Wrapf(err, "failed to save advisory")
		}
	}
	return nil
}

func (r *Rocky) Get(params db.GetParams) ([]types.Advisory, error) {
	eb := oops.In("rocky").With("release", params.Release).With("package_name", params.PkgName).With("arch", params.Arch)
	bucket := fmt.Sprintf(platformFormat, params.Release)
	rawAdvisories, err := r.ForEachAdvisory([]string{bucket}, params.PkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "unable to iterate advisories")
	}

	var advisories []types.Advisory
	for vulnID, v := range rawAdvisories {
		var adv types.Advisories
		if err = json.Unmarshal(v.Content, &adv); err != nil {
			return nil, eb.With("vuln_id", vulnID).Wrapf(err, "json unmarshal error")
		}

		// For backward compatibility
		// The old trivy-db has no entries, but has fixed versions and custom fields.
		if len(adv.Entries) == 0 {
			advisories = append(advisories, types.Advisory{
				VulnerabilityID: vulnID,
				FixedVersion:    adv.FixedVersion,
				DataSource:      &v.Source,
				Custom:          adv.Custom,
			})
			continue
		}

		for _, entry := range adv.Entries {
			if !slices.Contains(entry.Arches, params.Arch) {
				continue
			}
			entry.VulnerabilityID = vulnID
			entry.DataSource = &v.Source
			advisories = append(advisories, entry)
		}
	}

	return advisories, nil
}

func generalizeSeverity(severity string) types.Severity {
	switch strings.ToLower(severity) {
	case "low":
		return types.SeverityLow
	case "moderate":
		return types.SeverityMedium
	case "important":
		return types.SeverityHigh
	case "critical":
		return types.SeverityCritical
	}
	return types.SeverityUnknown
}

// fixedVersion checks for the arch and only updates version for `x86_64`
// only used for types.Advisories.FixedVersion for backward compatibility
func fixedVersion(prevVersion, newVersion, arch string) string {
	if arch == "x86_64" || arch == "noarch" {
		return newVersion
	}
	return prevVersion
}
