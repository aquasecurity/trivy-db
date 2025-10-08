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
	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/alpine"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/debian"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/ubuntu"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	rootioDir      = "rootio"
	feedFileName   = "cve_feed.json" // Feed filename for both OS and app feeds
	appSubDir      = "app"           // Subdirectory for app feed
	platformFormat = "root.io %s %s" // "root.io {baseOS} {version}"
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

	supportedEcosystems = []ecosystem.Type{
		ecosystem.Pip,
		ecosystem.Npm,
		ecosystem.RubyGems,
		ecosystem.Maven,
		ecosystem.Go,
		ecosystem.NuGet,
		ecosystem.Cargo,
	}
)

type config struct {
	dbc    db.Operation
	logger *log.Logger
}

type VulnSrc struct {
	supportedOSes       []types.SourceID
	supportedEcosystems []ecosystem.Type
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

// createBucketForEcosystem creates the appropriate bucket for the given ecosystem
func (vs VulnSrc) createBucketForEcosystem(eco ecosystem.Type, source types.DataSource) (bucket.DataSourceBucket, error) {
	switch eco {
	case ecosystem.Pip:
		return bucket.NewPyPI(source)
	case ecosystem.Npm:
		return bucket.NewNpm(source)
	case ecosystem.RubyGems:
		return bucket.NewRubyGems(source)
	case ecosystem.Maven:
		return bucket.NewMaven(source)
	case ecosystem.Go:
		return bucket.NewGo(source)
	case ecosystem.NuGet:
		return bucket.NewNuGet(source)
	case ecosystem.Cargo:
		return bucket.NewCargo(source)
	default:
		return nil, fmt.Errorf("unsupported ecosystem: %s", eco)
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

// openAndParseJSON opens a JSON file and decodes it into the provided target
func (vs VulnSrc) openAndParseJSON(filePath string, target any) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	return json.NewDecoder(file).Decode(target)
}

func (vs VulnSrc) updateOSPackages(dir string) error {
	feedFilePath := filepath.Join(dir, "vuln-list", rootioDir, feedFileName)
	eb := oops.In("rootio").With("file_path", feedFilePath)

	var rawFeed RawFeed
	if err := vs.openAndParseJSON(feedFilePath, &rawFeed); err != nil {
		return eb.Wrapf(err, "failed to read feed file %s", feedFilePath)
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
			distroVersion := distro.DistroVersion
			platformName := fmt.Sprintf(platformFormat, strings.ToLower(baseOS), distroVersion)

			// Convert packages to patches
			for _, pkg := range distro.Packages {
				pkgName := pkg.Pkg.Name
				cvesMap := pkg.Pkg.CVEs

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
		if err := vs.save(baseOS, feeds, types.SourceID(baseOS)); err != nil {
			return eb.Wrapf(err, "save error")
		}
	}

	return nil
}

func (vs VulnSrc) updateLanguagePackages(dir string) error {
	appFeedPath := filepath.Join(dir, "vuln-list", rootioDir, appSubDir, feedFileName)
	eb := oops.In("rootio").With("file_path", appFeedPath)

	var rawAppFeed RawAppFeed
	if err := vs.openAndParseJSON(appFeedPath, &rawAppFeed); err != nil {
		// App feed might not exist yet, skip if file not found
		if os.IsNotExist(err) {
			vs.logger.Debug("App feed not found")
			return nil
		}
		return eb.Wrapf(err, "failed to read app feed file %s", appFeedPath)
	}

	// Process each ecosystem in the combined feed
	for ecosystemStr, distroDataList := range rawAppFeed {
		eco := ecosystem.Type(ecosystemStr)

		// Check if this ecosystem is supported
		if !slices.Contains(vs.supportedEcosystems, eco) {
			vs.logger.Warn("Unsupported ecosystem in app feed", "ecosystem", eco)
			continue
		}

		// Create the appropriate bucket for the ecosystem
		bkt, err := vs.createBucketForEcosystem(eco, source)
		if err != nil {
			vs.logger.Warn("Failed to create bucket for ecosystem", "ecosystem", eco, "error", err)
			continue
		}
		bucketName := bkt.Name()
		feeds := make(map[string][]Feed)

		for _, distroData := range distroDataList {
			for _, pkg := range distroData.Packages {
				pkgName := pkg.Pkg.Name
				cvesMap := pkg.Pkg.CVEs

				for cveID, cveInfo := range cvesMap {
					feed := Feed{
						VulnerabilityID: cveID,
						PkgName:         pkgName,
						Patch: types.Advisory{
							VulnerableVersions: cveInfo.VulnerableRanges,
							PatchedVersions:    cveInfo.FixedVersions,
						},
					}
					feeds[bucketName] = append(feeds[bucketName], feed)
				}
			}
		}

		// Save feeds for the current ecosystem
		if err := vs.save(string(eco), feeds, ""); err != nil {
			return eb.Wrapf(err, "save error for ecosystem %s", eco)
		}
	}

	return nil
}

func (vs VulnSrc) save(name string, feeds map[string][]Feed, baseID types.SourceID) error {
	if baseID != "" {
		vs.logger.Info("Saving Root.io DB", "base_os", name)
	} else {
		vs.logger.Info("Saving Root.io Language DB", "ecosystem", name)
	}

	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		for bucketOrPlatform, platformFeeds := range feeds {
			dataSource := types.DataSource{
				ID:     source.ID,
				Name:   source.Name,
				URL:    source.URL,
				BaseID: baseID,
			}
			if err := vs.dbc.PutDataSource(tx, bucketOrPlatform, dataSource); err != nil {
				return oops.Wrapf(err, "failed to put data source")
			}
			if err := vs.commit(tx, bucketOrPlatform, platformFeeds); err != nil {
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

func (vs VulnSrc) commit(tx *bolt.Tx, bucketOrPlatform string, feeds []Feed) error {
	for _, feed := range feeds {
		if err := vs.put(tx, bucketOrPlatform, feed); err != nil {
			return oops.Wrapf(err, "put error")
		}
	}
	return nil
}

func (vs VulnSrc) put(tx *bolt.Tx, bucketOrPlatform string, feed Feed) error {
	eb := oops.With("bucket_or_platform", bucketOrPlatform).With("package", feed.PkgName).With("cve", feed.VulnerabilityID)

	// Both OS and language packages use PutAdvisoryDetail
	if err := vs.dbc.PutAdvisoryDetail(tx, feed.VulnerabilityID, feed.PkgName, []string{bucketOrPlatform}, feed.Patch); err != nil {
		return eb.Wrapf(err, "failed to save advisory")
	}

	// For optimization
	if err := vs.dbc.PutVulnerabilityID(tx, feed.VulnerabilityID); err != nil {
		return eb.Wrapf(err, "failed to save the vulnerability ID")
	}

	return nil
}

type VulnSrcGetter struct {
	baseOS types.SourceID
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

func (vs VulnSrcGetter) Get(params db.GetParams) ([]types.Advisory, error) {
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
