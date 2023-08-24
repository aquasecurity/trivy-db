package ghsa

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/bucket"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/exp/slices"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/xerrors"
	"io"
	"log"
	"path/filepath"
)

var (
	cocoapodsSpecDir = filepath.Join("cocoapods-specs", "Specs")
)

// updater updates GHSA Swift advisories for Cocoapods
// GHSA Swift advisories use URLs as package names
// But Cocoapods uses package names
// Parse `https://github.com/CocoaPods/Specs` to match package names and URLs
// And store the matched advisories in `cocoapods::GitHub Security Advisory Cocoapods`
type updater struct {
	dbc        db.Operation
	sourceName string
	bucketName string
	specs      map[string][]string // git -> pkg names
}

func newCocoapodsParser(dir string, dbc db.Operation) (updater, error) {
	specs, err := walkSpecs(dir)
	if err != nil {
		return updater{}, xerrors.Errorf("cocoapods walk error: %w", err)
	}

	ecosystemName := cases.Title(language.English).String(string(vulnerability.Cocoapods))
	sourceName := fmt.Sprintf(platformFormat, ecosystemName)
	bucketName := bucket.Name(string(vulnerability.Cocoapods), sourceName)

	return updater{
		sourceName: sourceName,
		bucketName: bucketName,
		dbc:        dbc,
		specs:      specs,
	}, nil
}

func walkSpecs(dir string) (map[string][]string, error) {
	log.Printf("Walk `Cocoapods Specs` to convert Swift URLs to Cocoapods package names")
	var specs = make(map[string][]string)
	err := utils.FileWalk(filepath.Join(dir, cocoapodsSpecDir), func(r io.Reader, path string) error {
		if filepath.Ext(path) != ".json" {
			return nil
		}
		var spec Spec
		if err := json.NewDecoder(r).Decode(&spec); err != nil {
			return xerrors.Errorf("failed to decode CocoaPods Spec: %w", err)
		}
		if spec.Source.Git != "" {
			// trim `https://` prefix and `.git` suffix to fit the format
			link := vulnerability.NormalizePkgName(vulnerability.Swift, spec.Source.Git)
			// some packages (or subpackages) can use same git url
			// we need to save all packages
			if names, ok := specs[link]; ok {
				if !slices.Contains(names, spec.Name) {
					specs[link] = append(specs[link], spec.Name)
				}
				return nil
			}
			specs[link] = []string{spec.Name}
		}
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("error in CocoaPods walk: %w", err)
	}
	return specs, nil
}

func (u updater) putDataSource(tx *bolt.Tx) error {
	err := u.dbc.PutDataSource(tx, u.bucketName, types.DataSource{
		ID:   sourceID,
		Name: u.sourceName,
		// Use `Swift` in URL instead of `Cocoapods`
		URL: fmt.Sprintf("https://github.com/advisories?query=type%%3Areviewed+ecosystem%%3A%s", vulnerability.Swift),
	})
	if err != nil {
		return xerrors.Errorf("failed to put data source: %w", err)
	}
	return nil
}

func (u updater) putAdvisoryDetail(tx *bolt.Tx, adv types.Advisory, vulnID, url string) error {
	for _, pkgName := range u.specs[url] {
		err := u.dbc.PutAdvisoryDetail(tx, vulnID, pkgName, []string{u.bucketName}, adv)
		if err != nil {
			return xerrors.Errorf("failed to save GHSA Cocoapods spec: %w", err)
		}
	}
	return nil
}
