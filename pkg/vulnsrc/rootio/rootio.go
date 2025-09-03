package rootio

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
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
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/alpine"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/debian"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/ubuntu"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	rootioDir       = "rootio"
	feedFileName    = "cve_feed.json"
	platformFormat  = "root.io %s %s" // "root.io {baseOS} {version}"
	ecosystemFormat = "root.io %s"    // "root.io {ecosystem}"
)

var (
	source = types.DataSource{
		ID:   vulnerability.RootIO,
		Name: "Root.io Security Patches",
		URL:  "https://api.root.io/external/patch_feed",
	}

	supportedOSes = []types.SourceID{
		vulnerability.Alpine,
		vulnerability.Debian,
		vulnerability.Ubuntu,
	}

	supportedEcosystems = []types.Ecosystem{
		vulnerability.Pip,
		vulnerability.Npm,
		vulnerability.RubyGems,
		vulnerability.Maven,
		vulnerability.Go,
		vulnerability.NuGet,
		vulnerability.Cargo,
	}
)

type config struct {
	dbc    db.Operation
	logger *log.Logger
}

type VulnSrc struct {
	supportedOSes       []types.SourceID
	supportedEcosystems []types.Ecosystem
	config
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		supportedOSes:       supportedOSes,
		supportedEcosystems: supportedEcosystems,
		config: config{
			dbc:    db.Config{},
			logger: log.WithPrefix("rootio"),
		},
	}
}

func (vs VulnSrc) Name() types.SourceID {
	return source.ID
}

func (vs VulnSrc) Update(dir string) error {
	// Process OS package feeds
	if err := vs.updateOSPackages(dir); err != nil {
		return err
	}

	// Process language ecosystem feeds
	return vs.updateLanguagePackages(dir)
}

func (vs VulnSrc) updateOSPackages(dir string) error {
	feedFilePath := filepath.Join(dir, "vuln-list", rootioDir, feedFileName)
	eb := oops.In("rootio").With("file_path", feedFilePath)

	feedFile, err := os.Open(feedFilePath)
	if err != nil {
		return eb.Wrapf(err, "failed to open feed file %s", feedFilePath)
	}
	defer feedFile.Close()

	var rawFeed RawFeed
	if err = json.NewDecoder(feedFile).Decode(&rawFeed); err != nil {
		return eb.With("file_path", feedFilePath).Wrapf(err, "json decode error")
	}

	// Take rawDistroData for each base OS
	for baseOS, rawDistroData := range rawFeed {
		if !slices.Contains(vs.supportedOSes, types.SourceID(baseOS)) {
			vs.logger.Warn("Unsupported base OS", "base_os", baseOS)
			continue

		}

		// platform => feeds
		feeds := make(map[string][]Feed)
		// Convert each distro version to our internal Feed format
		for _, distro := range rawDistroData {
			// Determine distro version from either format
			var distroVersion string
			if distro.DistroVersion != "" {
				// Old format
				distroVersion = distro.DistroVersion
			} else if distro.Distro != nil {
				// New format
				distroVersion = distro.Distro.Latest
			}
			platformName := fmt.Sprintf(platformFormat, strings.ToLower(baseOS), distroVersion)

			// Convert packages to patches
			for _, pkg := range distro.Packages {
				// Get package data from either format
				var pkgName string
				var cvesMap map[string]RawCVEInfo

				if pkg.Pkg != nil {
					// Old format
					pkgName = pkg.Pkg.Name
					cvesMap = pkg.Pkg.CVEs
				} else {
					// New format
					pkgName = pkg.Name
					cvesMap = pkg.CVEs
				}

				for cveID, cveInfo := range cvesMap {
					feed := Feed{
						VulnerabilityID: cveID,
						PkgName:         pkgName,
						Patch: types.Advisory{
							VulnerableVersions: cveInfo.VulnerableRanges,
							PatchedVersions:    cveInfo.FixedVersions,
						},
					}
					feeds[platformName] = append(feeds[platformName], feed)
				}
			}
		}

		// Save feeds for the current base OS
		if err = vs.save(baseOS, feeds); err != nil {
			return eb.Wrapf(err, "save error")
		}
	}

	return nil
}

func (vs VulnSrc) updateLanguagePackages(dir string) error {
	// Process each supported ecosystem
	for _, ecosystem := range vs.supportedEcosystems {
		feedFilePath := filepath.Join(dir, "vuln-list", rootioDir, string(ecosystem), "feed.json")
		eb := oops.In("rootio").With("ecosystem", ecosystem).With("file_path", feedFilePath)

		feedFile, err := os.Open(feedFilePath)
		if err != nil {
			// Language feeds might not exist yet, skip if file not found
			if os.IsNotExist(err) {
				vs.logger.Debug("Language feed not found", "ecosystem", ecosystem)
				continue
			}
			return eb.Wrapf(err, "failed to open feed file %s", feedFilePath)
		}

		var rawLangFeed RawLanguageFeed
		if err = json.NewDecoder(feedFile).Decode(&rawLangFeed); err != nil {
			feedFile.Close()
			return eb.With("file_path", feedFilePath).Wrapf(err, "json decode error")
		}
		feedFile.Close()

		// Convert to internal format
		platformName := fmt.Sprintf(ecosystemFormat, ecosystem)
		feeds := make(map[string][]Feed)

		for _, pkg := range rawLangFeed.Packages {
			for cveID, cveInfo := range pkg.CVEs {
				feed := Feed{
					VulnerabilityID: cveID,
					PkgName:         pkg.Name,
					Patch: types.Advisory{
						VulnerableVersions: cveInfo.VulnerableRanges,
						PatchedVersions:    cveInfo.FixedVersions,
					},
				}
				feeds[platformName] = append(feeds[platformName], feed)
			}
		}

		// Save feeds for the current ecosystem
		if err = vs.saveEcosystem(ecosystem, feeds); err != nil {
			return eb.Wrapf(err, "save error")
		}
	}

	return nil
}

func (vs VulnSrc) save(baseOS string, feeds map[string][]Feed) error {
	vs.logger.Info("Saving Root.io DB", "base_os", baseOS)
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		for platform, platformFeeds := range feeds {
			dataSource := types.DataSource{
				ID:     source.ID,
				Name:   source.Name + fmt.Sprintf(" (%s)", baseOS),
				URL:    source.URL,
				BaseID: types.SourceID(baseOS),
			}
			if err := vs.dbc.PutDataSource(tx, platform, dataSource); err != nil {
				return oops.Wrapf(err, "failed to put data source")
			}
			if err := vs.commit(tx, platform, platformFeeds); err != nil {
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

func (vs VulnSrc) saveEcosystem(ecosystem types.Ecosystem, feeds map[string][]Feed) error {
	vs.logger.Info("Saving Root.io Language DB", "ecosystem", ecosystem)
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		for platform, platformFeeds := range feeds {
			dataSource := types.DataSource{
				ID:   source.ID,
				Name: source.Name + fmt.Sprintf(" (%s)", ecosystem),
				URL:  source.URL,
			}
			if err := vs.dbc.PutDataSource(tx, platform, dataSource); err != nil {
				return oops.Wrapf(err, "failed to put data source")
			}
			if err := vs.commit(tx, platform, platformFeeds); err != nil {
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

func (vs VulnSrc) commit(tx *bolt.Tx, platform string, feeds []Feed) error {
	for _, feed := range feeds {
		if err := vs.put(tx, platform, feed); err != nil {
			return oops.Wrapf(err, "put error")
		}
	}
	return nil
}

func (vs VulnSrc) put(tx *bolt.Tx, platform string, feed Feed) error {
	eb := oops.With("platform", platform).With("package", feed.PkgName).With("cve", feed.VulnerabilityID)

	// Both OS and language packages use PutAdvisoryDetail
	if err := vs.dbc.PutAdvisoryDetail(tx, feed.VulnerabilityID, feed.PkgName, []string{platform}, feed.Patch); err != nil {
		return eb.Wrapf(err, "failed to save advisory")
	}

	// For optimization
	if err := vs.dbc.PutVulnerabilityID(tx, feed.VulnerabilityID); err != nil {
		return eb.Wrapf(err, "failed to save the vulnerability ID")
	}

	return nil
}

type VulnSrcGetter struct {
	baseOS    types.SourceID
	ecosystem types.Ecosystem
	config
}

// NewVulnSrcGetter creates a getter for OS packages
func NewVulnSrcGetter(baseOS types.SourceID) VulnSrcGetter {
	return VulnSrcGetter{
		baseOS: baseOS,
		config: config{
			dbc:    db.Config{},
			logger: log.WithPrefix(fmt.Sprintf("rootio-%s", baseOS)),
		},
	}
}

// NewEcosystemVulnSrcGetter creates a getter for language ecosystem packages
func NewEcosystemVulnSrcGetter(ecosystem types.Ecosystem) VulnSrcGetter {
	return VulnSrcGetter{
		ecosystem: ecosystem,
		config: config{
			dbc:    db.Config{},
			logger: log.WithPrefix(fmt.Sprintf("rootio-%s", ecosystem)),
		},
	}
}

func (vs VulnSrcGetter) Get(params db.GetParams) ([]types.Advisory, error) {
	// Check if this is for language packages (ecosystem) or OS packages
	if vs.ecosystem != "" {
		return vs.getEcosystemAdvisories(params)
	}
	return vs.getOSAdvisories(params)
}

func (vs VulnSrcGetter) getOSAdvisories(params db.GetParams) ([]types.Advisory, error) {
	eb := oops.In("rootio").With("base_os", vs.baseOS).With("os_version", params.Release).With("package_name", params.PkgName)
	// Get advisories from the original distributors, like Debian or Alpine
	advs, err := vs.baseOSGetter().Get(params)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get advisories for base OS")
	}

	// Simulate the advisories with Root.io's version constraints
	allAdvs := make(map[string]types.Advisory, len(advs))
	for _, adv := range advs {
		if adv.FixedVersion != "" {
			adv.VulnerableVersions = []string{"<" + adv.FixedVersion}
			adv.PatchedVersions = []string{adv.FixedVersion}
			adv.FixedVersion = "" // Clear fixed version to avoid confusion
		}
		allAdvs[adv.VulnerabilityID] = adv
	}

	rootioOSVer := fmt.Sprintf(platformFormat, vs.baseOS, params.Release)
	advs, err = vs.dbc.GetAdvisories(rootioOSVer, params.PkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get advisories")
	}

	rootAdvs := lo.SliceToMap(advs, func(adv types.Advisory) (string, types.Advisory) {
		// Debian may contain severity in the advisory.
		// We need to save this severity for the Root.io advisory.
		adv.Severity = allAdvs[adv.VulnerabilityID].Severity
		return adv.VulnerabilityID, adv
	})

	// Merge the advisories from the original distributors with Root.io's advisories.
	// If both have the same vulnerability ID - only Root.io recommendation will be kept.
	maps.Copy(allAdvs, rootAdvs)

	if len(allAdvs) == 0 {
		return nil, nil
	}

	allAdvsSlice := lo.Values(allAdvs)
	sort.Slice(allAdvsSlice, func(i, j int) bool {
		return allAdvsSlice[i].VulnerabilityID < allAdvsSlice[j].VulnerabilityID
	})

	return allAdvsSlice, nil
}

func (vs VulnSrcGetter) getEcosystemAdvisories(params db.GetParams) ([]types.Advisory, error) {
	eb := oops.In("rootio").With("ecosystem", vs.ecosystem).With("package_name", params.PkgName)

	// For language packages, we get advisories directly from Root.io
	platformName := fmt.Sprintf(ecosystemFormat, vs.ecosystem)
	advs, err := vs.dbc.GetAdvisories(platformName, params.PkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get advisories")
	}

	if len(advs) == 0 {
		return nil, nil
	}

	sort.Slice(advs, func(i, j int) bool {
		return advs[i].VulnerabilityID < advs[j].VulnerabilityID
	})

	return advs, nil
}

func (vs VulnSrcGetter) baseOSGetter() db.Getter {
	switch vs.baseOS {
	case vulnerability.Debian:
		return debian.NewVulnSrc()
	case vulnerability.Ubuntu:
		return ubuntu.NewVulnSrc()
	case vulnerability.Alpine:
		return alpine.NewVulnSrc()
	}
	return nil
}
