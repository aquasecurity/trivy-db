package ubuntu

import (
	"encoding/json"
	"io"
	"path/filepath"
	"slices"

	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const ubuntuDir = "ubuntu"

var (
	targetStatuses        = []string{"needed", "deferred", "released"}
	UbuntuReleasesMapping = map[string]string{
		"precise":  "12.04",
		"quantal":  "12.10",
		"raring":   "13.04",
		"saucy":    "13.10",
		"trusty":   "14.04",
		"utopic":   "14.10",
		"vivid":    "15.04",
		"wily":     "15.10",
		"xenial":   "16.04",
		"yakkety":  "16.10",
		"zesty":    "17.04",
		"artful":   "17.10",
		"bionic":   "18.04",
		"cosmic":   "18.10",
		"disco":    "19.04",
		"eoan":     "19.10",
		"focal":    "20.04",
		"groovy":   "20.10",
		"hirsute":  "21.04",
		"impish":   "21.10",
		"jammy":    "22.04",
		"kinetic":  "22.10",
		"lunar":    "23.04",
		"mantic":   "23.10",
		"noble":    "24.04",
		"oracular": "24.10",
		"plucky":   "25.04",
		"questing": "25.10",
		// ESM versions:
		"precise/esm": "12.04-ESM",
		"trusty/esm":  "14.04-ESM",
		// Possible multiple values for one release:
		// (release_list="trusty trusty/esm xenial esm-infra/xenial esm-apps/xenial bionic esm-infra/bionic esm-apps/bionic focal esm-apps/focal jammy esm-apps/jammy noble oracular plucky")
		// cf. https://wiki.ubuntu.com/SecurityTeam/BuildEnvironment#line867
		"esm-infra/xenial": "16.04-ESM",
		"esm-apps/xenial":  "16.04-ESM",
		"esm-infra/bionic": "18.04-ESM",
		"esm-apps/bionic":  "18.04-ESM",
		"esm-infra/focal":  "20.04-ESM",
		"esm-apps/focal":   "20.04-ESM",
	}

	source = types.DataSource{
		ID:   vulnerability.Ubuntu,
		Name: "Ubuntu CVE Tracker",
		URL:  "https://git.launchpad.net/ubuntu-cve-tracker",
	}
)

type Option func(src *VulnSrc)

func WithCustomPut(put db.CustomPut) Option {
	return func(src *VulnSrc) {
		src.put = put
	}
}

type VulnSrc struct {
	put    db.CustomPut
	dbc    db.Operation
	logger *log.Logger
}

func NewVulnSrc(opts ...Option) VulnSrc {
	src := VulnSrc{
		put:    defaultPut,
		dbc:    db.Config{},
		logger: log.WithPrefix("ubuntu"),
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
	rootDir := filepath.Join(dir, "vuln-list", ubuntuDir)
	eb := oops.In("ubuntu").With("root_dir", rootDir)
	var cves []UbuntuCVE
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var cve UbuntuCVE
		if err := json.NewDecoder(r).Decode(&cve); err != nil {
			return eb.With("file_path", path).Wrapf(err, "json decode error")
		}
		cves = append(cves, cve)
		return nil
	})
	if err != nil {
		return eb.Wrapf(err, "walk error")
	}

	if err = vs.save(cves); err != nil {
		return eb.Wrapf(err, "save error")
	}

	return nil
}

func (vs VulnSrc) save(cves []UbuntuCVE) error {
	vs.logger.Info("Saving DB")
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		err := vs.commit(tx, cves)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return oops.Wrapf(err, "batch update error")
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, cves []UbuntuCVE) error {
	for _, cve := range cves {
		if err := vs.put(vs.dbc, tx, cve); err != nil {
			return oops.Wrapf(err, "put error")
		}
	}
	return nil
}

func (vs VulnSrc) Get(params db.GetParams) ([]types.Advisory, error) {
	eb := oops.In("ubuntu").With("release", params.Release).With("package_name", params.PkgName)
	bucketName := bucket.NewUbuntu(params.Release).Name()
	advisories, err := vs.dbc.GetAdvisories(bucketName, params.PkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get advisories")
	}
	return advisories, nil
}

func defaultPut(dbc db.Operation, tx *bolt.Tx, advisory any) error {
	cve, ok := advisory.(UbuntuCVE)
	if !ok {
		return oops.Errorf("unknown type")
	}

	for packageName, patch := range cve.Patches {
		pkgName := string(packageName)
		for release, status := range patch {
			if !slices.Contains(targetStatuses, status.Status) {
				continue
			}
			osVersion, ok := UbuntuReleasesMapping[string(release)]
			if !ok {
				continue
			}
			platformName := bucket.NewUbuntu(osVersion).Name()
			if err := dbc.PutDataSource(tx, platformName, source); err != nil {
				return oops.Wrapf(err, "failed to put data source")
			}

			adv := types.Advisory{}
			if status.Status == "released" {
				adv.FixedVersion = status.Note
			}
			if err := dbc.PutAdvisoryDetail(tx, cve.Candidate, pkgName, []string{platformName}, adv); err != nil {
				return oops.Wrapf(err, "failed to save advisory")
			}

			vuln := types.VulnerabilityDetail{
				Severity:    SeverityFromPriority(cve.Priority),
				References:  cve.References,
				Description: cve.Description,
			}
			if err := dbc.PutVulnerabilityDetail(tx, cve.Candidate, source.ID, vuln); err != nil {
				return oops.Wrapf(err, "failed to save vulnerability")
			}

			// for optimization
			if err := dbc.PutVulnerabilityID(tx, cve.Candidate); err != nil {
				return oops.Wrapf(err, "failed to save the vulnerability ID")
			}
		}
	}

	return nil
}

// SeverityFromPriority converts Ubuntu priority into Trivy severity
func SeverityFromPriority(priority string) types.Severity {
	switch priority {
	case "untriaged":
		return types.SeverityUnknown
	case "negligible", "low":
		return types.SeverityLow
	case "medium":
		return types.SeverityMedium
	case "high":
		return types.SeverityHigh
	case "critical":
		return types.SeverityCritical
	default:
		return types.SeverityUnknown
	}
}
