package k8svulndb

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/samber/lo"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
	"io"
	"log"
	"path/filepath"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	vulnListDir = "vuln-list-k8s"
	apiDir      = "k8s/cves"
)

var (
	source = types.DataSource{
		ID:   vulnerability.K8sVulnDB,
		Name: "The k8s Vulnerability Database",
		URL:  "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json",
	}

	bucketName = bucket.Name(string(vulnerability.K8s), source.Name)
)

type VulnSrc struct {
	dbc db.Operation
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Name() types.SourceID {
	return vulnerability.K8sVulnDB
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, vulnListDir, apiDir)

	var cves []K8sCVE
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var cve K8sCVE
		if err := json.NewDecoder(r).Decode(&cve); err != nil {
			return xerrors.Errorf("JSON decode error (%s): %w", path, err)
		}
		cves = append(cves, cve)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("walk error: %w", err)
	}

	if err = vs.save(cves); err != nil {
		return xerrors.Errorf("save error: %w", err)
	}
	return nil
}

func (vs VulnSrc) save(items []K8sCVE) error {
	log.Println("Saving The k8s Vulnerability Database")
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		if err := vs.dbc.PutDataSource(tx, bucketName, source); err != nil {
			return xerrors.Errorf("failed to put data source: %w", err)
		}

		for _, item := range items {
			if err := vs.commit(tx, item); err != nil {
				return xerrors.Errorf("commit error (%s): %w", item.ID, err)
			}
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("batch update error: %w", err)
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, item K8sCVE) error {

	if len(item.AffectedVersions) == 0 {
		return nil
	}
	var patchedVersions, vulnerableVersions []string
	for _, introduced := range item.AffectedVersions {
		vulnerableVersions = append(vulnerableVersions, fmt.Sprintf("%s<=, <=%s", introduced.Introduced, introduced.LastAffected))
		patchedVersions = append(patchedVersions, introduced.Fixed)
	}
	a := types.Advisory{
		PatchedVersions:    lo.Map(item.AffectedVersions, func(v *Version, _ int) string { return v.Fixed }),
		VulnerableVersions: vulnerableVersions,
	}
	err := vs.dbc.PutAdvisoryDetail(tx, item.ID, item.Component, []string{bucketName}, a)
	if err != nil {
		return xerrors.Errorf("failed to save k8s-vulndb advisory: %w", err)
	}
	severity, err := types.NewSeverity(strings.ToUpper(item.Severity))
	if err != nil {
		severity = types.SeverityUnknown
	}
	publishedDate, err := time.Parse(time.RFC3339, item.CreatedAt)
	if err != nil {
		publishedDate = time.Now()
	}
	vuln := types.VulnerabilityDetail{
		ID:               item.ID,
		Severity:         severity,
		CvssVector:       item.CvssV3.Vector,
		Description:      item.Description,
		References:       item.Urls,
		CvssScoreV3:      item.CvssV3.Score,
		Title:            item.Summary,
		PublishedDate:    &publishedDate,
		LastModifiedDate: &publishedDate,
	}

	if err = vs.dbc.PutVulnerabilityDetail(tx, item.ID, source.ID, vuln); err != nil {
		return xerrors.Errorf("failed to put vulnerability detail (%s): %w", item.ID, err)
	}

	if err = vs.dbc.PutVulnerabilityID(tx, item.ID); err != nil {
		return xerrors.Errorf("failed to save the vulnerability ID: %w", err)
	}
	return nil
}
