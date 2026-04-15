package rootio

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
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
	rootioDir      = "rootio"
	platformFormat = "root.io %s %s" // "root.io {baseOS} {version}"
)

var source = types.DataSource{
	ID:   vulnerability.RootIO,
	Name: "Root.io Security Patches",
	URL:  "https://api.root.io/external/patch_feed",
}

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
	rootDir := filepath.Join(dir, "vuln-list", rootioDir)
	eb := oops.In("rootio").With("root_dir", rootDir)

	return vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return fs.WalkDir(os.DirFS(rootDir), ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".json") {
				return nil
			}

			f, err := os.Open(filepath.Join(rootDir, path))
			if err != nil {
				return eb.Wrapf(err, "open %s", path)
			}
			defer f.Close()

			var adv OSVAdvisory
			if err := json.NewDecoder(f).Decode(&adv); err != nil {
				return eb.With("path", path).Wrapf(err, "json decode error")
			}

			if len(adv.Affected) == 0 || len(adv.Upstream) == 0 {
				return nil
			}

			return vs.put(tx, adv)
		})
	})
}

func (vs VulnSrc) put(tx *bolt.Tx, adv OSVAdvisory) error {
	cveID := adv.Upstream[0]
	affected := adv.Affected[0]

	var fixedVersion string
	for _, r := range affected.Ranges {
		for _, e := range r.Events {
			if e.Fixed != "" {
				fixedVersion = e.Fixed
				break
			}
		}
		if fixedVersion != "" {
			break
		}
	}
	if fixedVersion == "" {
		return nil
	}

	platform := vs.platform(adv)

	ds := source
	if adv.DatabaseSpecific.Distro != "" {
		ds.Name = source.Name + fmt.Sprintf(" (%s)", adv.DatabaseSpecific.Distro)
		ds.BaseID = types.SourceID(adv.DatabaseSpecific.Distro)
	}

	eb := oops.With("platform", platform).With("package", affected.Package.Name).With("cve", cveID)

	if err := vs.dbc.PutDataSource(tx, platform, ds); err != nil {
		return eb.Wrapf(err, "failed to put data source")
	}

	advisory := types.Advisory{FixedVersion: fixedVersion}
	if err := vs.dbc.PutAdvisoryDetail(tx, cveID, affected.Package.Name, []string{platform}, advisory); err != nil {
		return eb.Wrapf(err, "failed to save advisory")
	}

	if err := vs.dbc.PutVulnerabilityID(tx, cveID); err != nil {
		return eb.Wrapf(err, "failed to save the vulnerability ID")
	}

	return nil
}

func (vs VulnSrc) platform(adv OSVAdvisory) string {
	distro := adv.DatabaseSpecific.Distro
	if distro == "" {
		// App advisory — use the ecosystem as the namespace.
		// Callers guard len(adv.Affected) > 0 before reaching here.
		return strings.ToLower(adv.Affected[0].Package.Ecosystem)
	}
	return fmt.Sprintf(platformFormat, distro, adv.DatabaseSpecific.DistroVersion)
}

type VulnSrcGetter struct {
	baseOS types.SourceID
	config
}

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
