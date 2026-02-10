package alinux

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	alinuxDir        = "alinux"
	alinuxCSAFVEXDir = "alinux-csaf-vex"
)

var (
	targetVersions = []string{
		"2",
		"3",
		"4",
	}

	source = types.DataSource{
		ID:   vulnerability.Alinux,
		Name: "Alibaba Cloud Linux Security Center",
		URL:  "https://alas.aliyuncs.com/",
	}
)

// VulnSrc is the vulnerability source for Alibaba Cloud Linux
type VulnSrc struct {
	dbc        db.Operation
	logger     *log.Logger
	advisories map[string][]ALSA
	vexDetails map[string]vexDetail // CVE-ID -> enriched details from VEX
}

// ALSA has detailed data of Alibaba Cloud Linux Security Advisory
type ALSA struct {
	ID          string      `json:"id,omitempty"`
	Title       string      `json:"title,omitempty"`
	Severity    string      `json:"severity,omitempty"`
	Description string      `json:"description,omitempty"`
	Packages    []Package   `json:"packages,omitempty"`
	References  []Reference `json:"references,omitempty"`
	CveIDs      []string    `json:"cveids,omitempty"`
}

// Package has affected package information
type Package struct {
	Name    string `json:"name,omitempty"`
	Epoch   string `json:"epoch,omitempty"`
	Version string `json:"version,omitempty"`
	Release string `json:"release,omitempty"`
}

// Reference has reference information
type Reference struct {
	ID     string `json:"id,omitempty"`
	Href   string `json:"href,omitempty"`
	Cvss3  string `json:"cvss3,omitempty"`
	Impact string `json:"impact,omitempty"`
}

// vexDetail holds enriched vulnerability info from CSAF VEX data
type vexDetail struct {
	Description  string
	Severity     string
	CvssVectorV3 string
	CvssScoreV3  float64
}

// csafVEXDocument is a minimal struct to parse CSAF VEX JSON
type csafVEXDocument struct {
	Document struct {
		AggregateSeverity struct {
			Text string `json:"text"`
		} `json:"aggregate_severity"`
		Notes []struct {
			Category string `json:"category"`
			Text     string `json:"text"`
		} `json:"notes"`
		Tracking struct {
			ID string `json:"id"`
		} `json:"tracking"`
	} `json:"document"`
	Vulnerabilities []struct {
		CVE    string `json:"cve"`
		Notes  []struct {
			Category string `json:"category"`
			Text     string `json:"text"`
		} `json:"notes,omitempty"`
		Scores []struct {
			CvssV3 struct {
				BaseScore    float64 `json:"baseScore"`
				VectorString string  `json:"vectorString"`
			} `json:"cvss_v3"`
		} `json:"scores,omitempty"`
		Threats []struct {
			Category string `json:"category"`
			Details  string `json:"details"`
		} `json:"threats,omitempty"`
		ProductStatus struct {
			Fixed           []string `json:"fixed,omitempty"`
			KnownNotAffected []string `json:"known_not_affected,omitempty"`
		} `json:"product_status"`
	} `json:"vulnerabilities"`
	ProductTree struct {
		Relationships []struct {
			ProductReference          string `json:"product_reference"`
			RelatesToProductReference string `json:"relates_to_product_reference"`
			FullProductName           struct {
				ProductID string `json:"product_id"`
			} `json:"full_product_name"`
		} `json:"relationships"`
	} `json:"product_tree"`
}

// productVersionRe extracts major version from product names like "Alinux 2.1903", "Alinux 3.2104", "Alinux 4"
var productVersionRe = regexp.MustCompile(`(?i)Alinux\s+(\d+)`)

// NewVulnSrc creates a new VulnSrc
func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc:        db.Config{},
		logger:     log.WithPrefix("alinux"),
		advisories: map[string][]ALSA{},
		vexDetails: map[string]vexDetail{},
	}
}

// Name returns the source ID
func (vs VulnSrc) Name() types.SourceID {
	return source.ID
}

// Update reads JSON advisories and CSAF VEX data from the vuln-list cache and saves them to the database
func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", alinuxDir)
	eb := oops.In("alinux").With("root_dir", rootDir)

	err := utils.FileWalk(rootDir, vs.walkFunc)
	if err != nil {
		return eb.Wrapf(err, "walk error")
	}

	// Process CSAF VEX data for enrichment (optional, may not exist)
	vexDir := filepath.Join(dir, "vuln-list", alinuxCSAFVEXDir)
	if _, statErr := os.Stat(vexDir); statErr == nil {
		vs.logger.Info("Processing CSAF VEX data for enrichment", "dir", vexDir)
		if walkErr := utils.FileWalk(vexDir, vs.walkVEXFunc); walkErr != nil {
			vs.logger.Warn("Failed to process VEX data, continuing with advisory data only", "error", walkErr)
		} else {
			vs.logger.Info("Loaded VEX details", "count", len(vs.vexDetails))
		}
	}

	if err = vs.save(); err != nil {
		return eb.Wrapf(err, "save error")
	}

	return nil
}

func (vs *VulnSrc) walkFunc(r io.Reader, path string) error {
	paths := strings.Split(path, string(filepath.Separator))
	if len(paths) < 2 {
		return nil
	}
	version := paths[len(paths)-2]
	if !slices.Contains(targetVersions, version) {
		vs.logger.Warn("Unsupported Alinux version", "version", version)
		return nil
	}

	var alsa ALSA
	if err := json.NewDecoder(r).Decode(&alsa); err != nil {
		return oops.With("file_path", path).With("version", version).Wrapf(err, "json decode error")
	}

	vs.advisories[version] = append(vs.advisories[version], alsa)
	return nil
}

func (vs *VulnSrc) walkVEXFunc(r io.Reader, path string) error {
	var doc csafVEXDocument
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return oops.With("file_path", path).Wrapf(err, "json decode error")
	}

	for _, vuln := range doc.Vulnerabilities {
		if vuln.CVE == "" {
			continue
		}

		detail := vexDetail{
			Severity: doc.Document.AggregateSeverity.Text,
		}

		// Extract description from vulnerability notes
		for _, note := range vuln.Notes {
			if note.Category == "description" {
				detail.Description = note.Text
				break
			}
		}

		// Extract CVSS v3 info
		if len(vuln.Scores) > 0 {
			detail.CvssVectorV3 = vuln.Scores[0].CvssV3.VectorString
			detail.CvssScoreV3 = vuln.Scores[0].CvssV3.BaseScore
		}

		// Use per-CVE threat severity if available
		for _, t := range vuln.Threats {
			if t.Category == "impact" && t.Details != "" {
				detail.Severity = t.Details
				break
			}
		}

		vs.vexDetails[vuln.CVE] = detail
	}

	return nil
}

func (vs VulnSrc) save() error {
	vs.logger.Info("Saving DB")
	err := vs.dbc.BatchUpdate(vs.commit)
	if err != nil {
		return oops.Wrapf(err, "batch update error")
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx) error {
	for majorVersion, alsaList := range vs.advisories {
		platformName := bucket.NewAlinux(majorVersion).Name()

		if err := vs.dbc.PutDataSource(tx, platformName, source); err != nil {
			return oops.Wrapf(err, "failed to put data source")
		}
		for _, alsa := range alsaList {
			for _, cveID := range alsa.CveIDs {
				for _, pkg := range alsa.Packages {
					advisory := types.Advisory{
						FixedVersion: utils.ConstructVersion(pkg.Epoch, pkg.Version, pkg.Release),
					}
					if err := vs.dbc.PutAdvisoryDetail(tx, cveID, pkg.Name, []string{platformName}, advisory); err != nil {
						return oops.Wrapf(err, "failed to save advisory")
					}
				}

				var references []string
				for _, ref := range alsa.References {
					references = append(references, ref.Href)
				}

				// Build vulnerability detail, starting with advisory data
				vuln := types.VulnerabilityDetail{
					Severity:    severityFromPriority(alsa.Severity),
					References:  references,
					Description: alsa.Description,
				}

				// Enrich with CVSS v3 data from advisory references
				for _, ref := range alsa.References {
					if ref.Cvss3 != "" {
						vuln.CvssVectorV3 = ref.Cvss3
						break
					}
				}

				// Enrich with VEX data if available (more detailed description and CVSS score)
				if vex, ok := vs.vexDetails[cveID]; ok {
					if vex.Description != "" {
						vuln.Description = vex.Description
					}
					if vex.CvssVectorV3 != "" {
						vuln.CvssVectorV3 = vex.CvssVectorV3
					}
					if vex.CvssScoreV3 > 0 {
						vuln.CvssScoreV3 = vex.CvssScoreV3
					}
					if vex.Severity != "" {
						vuln.Severity = severityFromPriority(vex.Severity)
					}
				}

				if err := vs.dbc.PutVulnerabilityDetail(tx, cveID, source.ID, vuln); err != nil {
					return oops.Wrapf(err, "failed to save vulnerability detail")
				}

				// for optimization
				if err := vs.dbc.PutVulnerabilityID(tx, cveID); err != nil {
					return oops.Wrapf(err, "failed to save vulnerability ID")
				}
			}
		}
	}
	return nil
}

// Get returns security advisories for a given release and package
func (vs VulnSrc) Get(params db.GetParams) ([]types.Advisory, error) {
	eb := oops.In("alinux").With("release", params.Release)
	platformName := bucket.NewAlinux(params.Release).Name()
	advisories, err := vs.dbc.GetAdvisories(platformName, params.PkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get advisories")
	}
	return advisories, nil
}

func severityFromPriority(priority string) types.Severity {
	switch strings.ToLower(priority) {
	case "low":
		return types.SeverityLow
	case "moderate", "medium":
		return types.SeverityMedium
	case "important", "high":
		return types.SeverityHigh
	case "critical":
		return types.SeverityCritical
	default:
		return types.SeverityUnknown
	}
}
