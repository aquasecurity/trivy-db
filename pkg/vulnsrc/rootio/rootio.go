package rootio

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/samber/lo"
	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/alpine"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/debian"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/ubuntu"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	rootioDir      = "rootio"
	platformFormat = "root.io %s %s" // "root.io {baseOS} {version}"
)

var (
	source = types.DataSource{
		ID:   vulnerability.RootIO,
		Name: "Root.io Security Patches",
		URL:  "https://api.root.io/external/patch_feed",
	}
)

type VulnSrc struct {
	baseOS types.SourceID
	dbc    db.Operation
	logger *log.Logger
}

func NewVulnSrc(baseOS types.SourceID) VulnSrc {
	return VulnSrc{
		baseOS: baseOS,
		dbc:    db.Config{},
		logger: log.WithPrefix(fmt.Sprintf("rootio-%s", baseOS)),
	}
}

func (vs VulnSrc) Name() types.SourceID {
	return source.ID
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", rootioDir)
	eb := oops.In("rootio").With("root_dir", rootDir).With("base_os", vs.baseOS)

	// platform => feeds
	feeds := make(map[string][]Feed)
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var rawFeed RawFeed
		if err := json.NewDecoder(r).Decode(&rawFeed); err != nil {
			return eb.With("file_path", path).Wrapf(err, "json decode error")
		}

		// Extract data for our specific base OS and convert to internal format
		var rawDistroData []RawDistroData
		switch vs.baseOS {
		case vulnerability.Alpine:
			rawDistroData = rawFeed.Alpine
		case vulnerability.Debian:
			rawDistroData = rawFeed.Debian
		case vulnerability.Ubuntu:
			rawDistroData = rawFeed.Ubuntu
		}

		// Convert each distro version to our internal Feed format
		for _, distro := range rawDistroData {
			platformName := fmt.Sprintf(platformFormat, strings.ToLower(string(vs.baseOS)), distro.DistroVersion)

			// Convert packages to patches
			for _, pkg := range distro.Packages {
				for cveID, cveInfo := range pkg.Pkg.CVEs {
					feed := Feed{
						VulnerabilityID: cveID,
						PkgName:         pkg.Pkg.Name,
						Patch: types.Advisory{
							VulnerableVersions: cveInfo.VulnerableRanges,
							PatchedVersions:    cveInfo.FixedVersions,
						},
					}
					feeds[platformName] = append(feeds[platformName], feed)
				}
			}
		}

		return nil
	})
	if err != nil {
		return eb.Wrapf(err, "walk error")
	}

	if err = vs.save(feeds); err != nil {
		return eb.Wrapf(err, "save error")
	}

	return nil
}

func (vs VulnSrc) save(feeds map[string][]Feed) error {
	vs.logger.Info("Saving Root.io DB", "base_os", vs.baseOS)
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		for platform, platformFeeds := range feeds {
			if err := vs.dbc.PutDataSource(tx, platform, source); err != nil {
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

	if err := vs.dbc.PutAdvisoryDetail(tx, feed.VulnerabilityID, feed.PkgName, []string{platform}, feed.Patch); err != nil {
		return eb.Wrapf(err, "failed to save advisory")
	}

	// For optimization
	if err := vs.dbc.PutVulnerabilityID(tx, feed.VulnerabilityID); err != nil {
		return eb.Wrapf(err, "failed to save the vulnerability ID")
	}

	return nil
}

func (vs VulnSrc) Get(osVer, pkgName string) ([]types.Advisory, error) {
	eb := oops.In("rootio").With("base_os", vs.baseOS).With("os_version", osVer).With("package_name", pkgName)
	// Get advisories from the original distributors, like Debian or Alpine
	advs, err := vs.baseOSGetter().Get(osVer, pkgName)
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

	rootioOSVer := fmt.Sprintf(platformFormat, vs.baseOS, osVer)
	advs, err = vs.dbc.GetAdvisories(rootioOSVer, pkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get advisories")
	}

	rootAdvs := lo.SliceToMap(advs, func(adv types.Advisory) (string, types.Advisory) {
		return adv.VulnerabilityID, adv
	})

	// // Merge the advisories from the original distributors with Root.io's advisories.
	// If both have the same vulnerability ID - only Root.io recommendation will be kept.
	maps.Copy(allAdvs, rootAdvs)

	return slices.Collect(maps.Values(allAdvs)), nil
}

func (vs VulnSrc) baseOSGetter() db.Getter {
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
