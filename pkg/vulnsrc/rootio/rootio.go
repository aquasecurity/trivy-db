package rootio

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"sort"

	"github.com/samber/lo"
	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/alpine"
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
)

type config struct {
	dbc    db.Operation
	logger *log.Logger
}

type VulnSrc struct {
	config
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
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
	// By default, update OS feeds first, then app feeds
	if err := vs.updatePackages(dir, false); err != nil { // OS feeds
		return err
	}
	return vs.updatePackages(dir, true) // App feeds
}

// updatePackages ingests Root.io feeds for either OS (appFeed=false) or language ecosystems (appFeed=true).
func (vs VulnSrc) updatePackages(dir string, appFeed bool) error {
	feedPath := filepath.Join(dir, "vuln-list", rootioDir, feedFileName) // OS feed path
	if appFeed {
		feedPath = filepath.Join(dir, "vuln-list", rootioDir, appSubDir, feedFileName) // App feed path
	}

	eb := oops.In("rootio").With("file_path", feedPath)

	// Both OS and app feeds have the same shape: map[string][]RawDistroData
	rawFeed := RawFeed{}
	f, err := os.Open(feedPath)
	if err != nil {
		return eb.Wrapf(err, "failed to open feed file %s", feedPath)
	}
	defer f.Close()

	if err = json.NewDecoder(f).Decode(&rawFeed); err != nil {
		return eb.Wrapf(err, "failed to parse feed file %s", feedPath)
	}

	for e, distroDataList := range rawFeed {
		feeds := make(map[string][]Feed)
		eco := ecosystem.Type(e)
		for _, distro := range distroDataList {
			bkt, err := newBucket(eco, distro.DistroVersion)
			// We check unsupported OS/ecosystem here
			if err != nil {
				vs.logger.Warn("Failed to initialize bucket", log.Err(err))
				continue
			}
			bktName := bkt.Name()
			for _, pkg := range distro.Packages {
				pkgName := pkg.Pkg.Name
				for cveID, cveInfo := range pkg.Pkg.CVEs {
					feed := Feed{
						VulnerabilityID: cveID,
						PkgName:         pkgName,
						Patch: types.Advisory{
							VulnerableVersions: cveInfo.VulnerableRanges,
							PatchedVersions:    cveInfo.FixedVersions,
						},
					}
					feeds[bktName] = append(feeds[bktName], feed)
				}
			}
		}
		vs.logger.Info("Saving Root.io DB", "ecosystem", eco)
		if err = vs.save(feeds, baseID(eco)); err != nil {
			return eb.Wrapf(err, "save error for ecosystem %s", eco)
		}
	}

	return nil
}

func (vs VulnSrc) save(feeds map[string][]Feed, baseID types.SourceID) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		for bucketOrPlatform, platformFeeds := range feeds {
			dataSource := types.DataSource{
				ID:   source.ID,
				Name: source.Name,
				URL:  source.URL,
				// For OS advisories only
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

// baseID returns the base source ID for the OS ecosystem only.
func baseID(eco ecosystem.Type) types.SourceID {
	switch eco {
	case ecosystem.Alpine:
		return vulnerability.Alpine
	case ecosystem.Debian:
		return vulnerability.Debian
	case ecosystem.Ubuntu:
		return vulnerability.Ubuntu
	}
	return ""
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
