/*
 * Copyright (c) 2022 Wind River Systems, Inc.
 *
 * The right to copy, distribute, modify, or otherwise make use
 * of this software may be licensed only pursuant to the terms
 * of an applicable Wind River license agreement.
 */

package wrlinux

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"strings"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	ustrings "github.com/aquasecurity/trivy-db/pkg/utils/strings"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	wrlinuxDir      = "wrlinux"
	platformFormat 	= "WRLinux OS %s"
)

var (
	targetStatuses = []string{"pending", "released"}

	source = types.DataSource{
		ID:   vulnerability.WRLinux,
		Name: "WRLinux OS CVE metadata",
		URL:  "https://support2.windriver.com",
	}
)

type Option func(src *VulnSrc)

func WithCustomPut(put db.CustomPut) Option {
	return func(src *VulnSrc) {
		src.put = put
	}
}

type VulnSrc struct {
	put db.CustomPut
	dbc db.Operation
}

func NewVulnSrc(opts ...Option) VulnSrc {
	src := VulnSrc{
		put: defaultPut,
		dbc: db.Config{},
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
	rootDir := filepath.Join(dir, "vuln-list", wrlinuxDir)
	var cves []WRLinuxCVE
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var cve WRLinuxCVE
		if err := json.NewDecoder(r).Decode(&cve); err != nil {
			return xerrors.Errorf("failed to decode WRLinux JSON: %w", err)
		}
		cves = append(cves, cve)
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in wrlinux walk: %w", err)
	}

	if err = vs.save(cves); err != nil {
		return xerrors.Errorf("error in wrlinux save: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(cves []WRLinuxCVE) error {
	log.Println("Saving wrlinux DB")
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		err := vs.commit(tx, cves)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, cves []WRLinuxCVE) error {
	for _, cve := range cves {
		if err := vs.put(vs.dbc, tx, cve); err != nil {
			return xerrors.Errorf("put error: %w", err)
		}
	}
	return nil
}

func (vs VulnSrc) Get(osVer string, pkgName string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, OsVerToRelease(osVer))
	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get wrlinux advisories: %w", err)
	}
	return advisories, nil
}

func defaultPut(dbc db.Operation, tx *bolt.Tx, advisory interface{}) error {
	cve, ok := advisory.(WRLinuxCVE)
	if !ok {
		return xerrors.New("unknown type")
	}
	for packageName, patch := range cve.Patches {
		pkgName := string(packageName)
		for osVer, status := range patch {
			if !ustrings.InSlice(status.Status, targetStatuses) {
				continue
			}
			release := OsVerToRelease(string(osVer))
			platformName := fmt.Sprintf(platformFormat, release)
			if err := dbc.PutDataSource(tx, platformName, source); err != nil {
				return xerrors.Errorf("failed to put data source: %w", err)
			}

			adv := types.Advisory{}
			if status.Status == "released" {
				adv.FixedVersion = status.Note
			}
			if err := dbc.PutAdvisoryDetail(tx, cve.Candidate, pkgName, []string{platformName}, adv); err != nil {
				return xerrors.Errorf("failed to save wrlinux advisory: %w", err)
			}

			vuln := types.VulnerabilityDetail{
				Severity:    SeverityFromPriority(cve.Priority),
				References:  cve.References,
				Description: cve.Description,
			}
			if err := dbc.PutVulnerabilityDetail(tx, cve.Candidate, source.ID, vuln); err != nil {
				return xerrors.Errorf("failed to save wrlinux vulnerability: %w", err)
			}

			// for optimization
			if err := dbc.PutVulnerabilityID(tx, cve.Candidate); err != nil {
				return xerrors.Errorf("failed to save the vulnerability ID: %w", err)
			}
		}
	}

	return nil
}

// SeverityFromPriority converts wrlinux priority into Trivy severity
func SeverityFromPriority(priority string) types.Severity {
	switch priority {
	case "new":
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

// gets the release from the osVersion
// "w.x.y.z" -> "w.x"
func OsVerToRelease(osVer string) string {
	s := strings.Split(osVer, ".")
	if s[len(s)-1] == "0" {
		return "LINCD"
	}
	return strings.Join(s[:2], ".")
}
