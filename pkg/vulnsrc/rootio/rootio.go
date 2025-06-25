package rootio

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
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
		URL:  "https://root.io/",
	}
)

type Option func(src *VulnSrc)

type VulnSrc struct {
	baseOS OSType
	put    db.CustomPut
	dbc    db.Operation
	logger *log.Logger
}

func NewVulnSrc(baseOS OSType, opts ...Option) VulnSrc {
	src := VulnSrc{
		baseOS: baseOS,
		put:    defaultPut,
		dbc:    db.Config{},
		logger: log.WithPrefix(fmt.Sprintf("rootio-%s", baseOS)),
	}

	for _, o := range opts {
		o(&src)
	}

	return src
}

func (vs VulnSrc) Name() types.SourceID {
	return source.ID
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", rootioDir)
	eb := oops.In("rootio").With("root_dir", rootDir).With("base_os", vs.baseOS)

	var feeds []RootIOFeed
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var rawFeed RawRootIOFeed
		if err := json.NewDecoder(r).Decode(&rawFeed); err != nil {
			return eb.With("file_path", path).Wrapf(err, "json decode error")
		}

		// Extract data for our specific base OS and convert to internal format
		var rawDistroData []RawDistroData
		switch vs.baseOS {
		case Alpine:
			rawDistroData = rawFeed.Alpine
		case Debian:
			rawDistroData = rawFeed.Debian
		case Ubuntu:
			rawDistroData = rawFeed.Ubuntu
		}

		// Convert each distro version to our internal RootIOFeed format
		for _, distro := range rawDistroData {
			feed := RootIOFeed{
				BaseOS:  string(vs.baseOS),
				Version: distro.DistroVersion,
				Patches: make(map[string][]Patch),
			}

			// Convert packages to patches
			for _, pkg := range distro.Packages {
				for cveID, cveInfo := range pkg.Pkg.CVEs {
					patch := Patch{
						VulnerabilityID:    cveID,
						VulnerableVersions: cveInfo.VulnerableRanges,
					}
					// Use first fixed version if available
					if len(cveInfo.FixedVersions) > 0 {
						patch.FixedVersion = cveInfo.FixedVersions[0]
					}
					feed.Patches[pkg.Pkg.Name] = append(feed.Patches[pkg.Pkg.Name], patch)
				}
			}

			if len(feed.Patches) > 0 {
				feeds = append(feeds, feed)
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

func (vs VulnSrc) save(feeds []RootIOFeed) error {
	vs.logger.Info("Saving Root.io DB", "base_os", vs.baseOS)
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		for _, feed := range feeds {
			if err := vs.commit(tx, feed); err != nil {
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

func (vs VulnSrc) commit(tx *bolt.Tx, feed RootIOFeed) error {
	eb := oops.With("base_os", feed.BaseOS).With("version", feed.Version)

	// Create platform bucket name: "root.io {baseOS} {version}"
	platformName := fmt.Sprintf(platformFormat, strings.ToLower(feed.BaseOS), feed.Version)

	if err := vs.dbc.PutDataSource(tx, platformName, source); err != nil {
		return eb.Wrapf(err, "failed to put data source")
	}

	for pkgName, patches := range feed.Patches {
		for _, patch := range patches {
			patchData := PatchData{
				PlatformName: platformName,
				PackageName:  pkgName,
				Patch:        patch,
			}
			if err := vs.put(vs.dbc, tx, patchData); err != nil {
				return eb.With("package", pkgName).With("cve", patch.VulnerabilityID).Wrapf(err, "put error")
			}
		}
	}
	return nil
}

func (vs VulnSrc) Get(osVer, pkgName string) ([]types.Advisory, error) {
	eb := oops.In("rootio").With("base_os", vs.baseOS).With("os_version", osVer).With("package_name", pkgName)

	// Generate bucket name: "root.io {baseOS} {osVer}"
	bucket := fmt.Sprintf(platformFormat, string(vs.baseOS), osVer)
	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get advisories")
	}
	return advisories, nil
}

type PatchData struct {
	PlatformName string
	PackageName  string
	Patch        Patch
}

func defaultPut(dbc db.Operation, tx *bolt.Tx, advisory any) error {
	patchData, ok := advisory.(PatchData)
	if !ok {
		return oops.Errorf("unknown type")
	}

	eb := oops.With("platform", patchData.PlatformName).With("package", patchData.PackageName).With("cve", patchData.Patch.VulnerabilityID)

	// Create advisory with constraint format in VulnerableVersions
	adv := types.Advisory{
		VulnerableVersions: patchData.Patch.VulnerableVersions, // Store constraint format here
	}

	// Set fixed version if available
	if patchData.Patch.FixedVersion != "" {
		adv.FixedVersion = patchData.Patch.FixedVersion
	}

	if err := dbc.PutAdvisoryDetail(tx, patchData.Patch.VulnerabilityID, patchData.PackageName, []string{patchData.PlatformName}, adv); err != nil {
		return eb.Wrapf(err, "failed to save advisory")
	}

	// For optimization
	if err := dbc.PutVulnerabilityID(tx, patchData.Patch.VulnerabilityID); err != nil {
		return eb.Wrapf(err, "failed to save the vulnerability ID")
	}

	return nil
}
