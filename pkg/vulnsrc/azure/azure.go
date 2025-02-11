package azure

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/azure/oval"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

type Distribution int

const (
	Azure Distribution = iota
	Mariner

	azureDir            = "azure"
	azurePlatformFormat = "Azure Linux %s"

	marinerDir            = "mariner"
	marinerPlatformFormat = "CBL-Mariner %s"
)

var (
	ErrNotSupported = oops.Errorf("format not supported")

	azureSource = types.DataSource{
		ID:   vulnerability.AzureLinux,
		Name: "Azure Linux Vulnerability Data",
		URL:  "https://github.com/microsoft/AzureLinuxVulnerabilityData",
	}

	marinerSource = types.DataSource{
		ID:   vulnerability.CBLMariner,
		Name: "CBL-Mariner Vulnerability Data",
		URL:  "https://github.com/microsoft/AzureLinuxVulnerabilityData",
	}
)

type resolvedTest struct {
	Name     string
	Version  string
	Operator operator
}

type VulnSrc struct {
	dbc            db.Operation
	logger         *log.Logger
	azureDir       string
	source         types.DataSource
	platformFormat string
}

func NewVulnSrc(dist Distribution) VulnSrc {
	vulnSrc := azureVulnSrc()
	if dist == Mariner {
		vulnSrc = marinerVulnSrc()
	}
	return vulnSrc
}

func azureVulnSrc() VulnSrc {
	return VulnSrc{
		dbc:            db.Config{},
		logger:         log.WithPrefix("azure"),
		azureDir:       azureDir,
		source:         azureSource,
		platformFormat: azurePlatformFormat,
	}
}

func marinerVulnSrc() VulnSrc {
	return VulnSrc{
		dbc:            db.Config{},
		logger:         log.WithPrefix("mariner"),
		azureDir:       marinerDir,
		source:         marinerSource,
		platformFormat: marinerPlatformFormat,
	}
}

func (vs VulnSrc) Name() types.SourceID {
	return vs.source.ID
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", vs.azureDir)
	eb := oops.In(string(vs.source.ID)).With("root_dir", rootDir)

	versions, err := os.ReadDir(rootDir)
	if err != nil {
		return eb.Wrapf(err, "unable to list directory entries")
	}

	for _, ver := range versions {
		versionDir := filepath.Join(rootDir, ver.Name())
		eb := eb.With("version_dir", versionDir)

		entries, err := vs.parseOVAL(versionDir)
		if err != nil {
			return eb.Wrapf(err, "failed to parse OVAL")
		}

		if err = vs.save(ver.Name(), entries); err != nil {
			return eb.Wrapf(err, "save error")
		}
	}

	return nil
}

func (vs VulnSrc) parseOVAL(dir string) ([]Entry, error) {
	vs.logger.Info("Parsing OVAL", log.DirPath(dir))

	// Parse and resolve tests
	tests, err := resolveTests(dir)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to resolve tests")
	}

	defs, err := oval.ParseDefinitions(dir)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to parse definitions")
	}

	return resolveDefinitions(defs, tests), nil
}

func resolveDefinitions(defs []oval.Definition, tests map[string]resolvedTest) []Entry {
	var entries []Entry

	for _, def := range defs {
		// `Criterion` may contain a multiple testRefs
		// e.g. `earlier than 1.20.7-1` and `greater than 0.0.0`
		// cf. https://github.com/aquasecurity/vuln-list-update/pull/313
		for _, criterion := range def.Criteria.Criterion {
			// `tests` contains only supported operators
			test, ok := tests[criterion.TestRef]
			if !ok {
				continue
			}
			entry := Entry{
				PkgName:  test.Name,
				Version:  test.Version,
				Operator: test.Operator,
				Metadata: def.Metadata,
			}

			entries = append(entries, entry)
		}
	}
	return entries
}

const (
	lte operator = "less than or equal"
	lt  operator = "less than"
	gt  operator = "greater than"
)

func resolveTests(dir string) (map[string]resolvedTest, error) {
	objects, err := oval.ParseObjects(dir)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to parse objects")
	}

	states, err := oval.ParseStates(dir)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to parse states")
	}

	tt, err := oval.ParseTests(dir)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to parse tests")
	}

	tests := map[string]resolvedTest{}
	for _, test := range tt.RpminfoTests {
		// test directive has should be "at least one"
		if test.Check != "at least one" {
			continue
		}

		t, err := followTestRefs(test, objects, states)
		if err != nil {
			return nil, oops.Wrapf(err, "unable to follow test refs")
		}

		if t.Name != "" {
			tests[test.ID] = t
		}
	}

	return tests, nil
}

func followTestRefs(test oval.RpmInfoTest, objects map[string]string, states map[string]oval.RpmInfoState) (resolvedTest, error) {
	eb := oops.With("object_ref", test.Object.ObjectRef).With("state_ref", test.State.StateRef).With("test_ref", test.ID)

	// Follow object ref
	if test.Object.ObjectRef == "" {
		return resolvedTest{}, eb.Errorf("invalid test, no object ref")
	}

	pkgName, ok := objects[test.Object.ObjectRef]
	if !ok {
		return resolvedTest{}, eb.Errorf("invalid test data, can't find object ref")
	}

	// Follow state ref
	if test.State.StateRef == "" {
		return resolvedTest{}, eb.Errorf("invalid test, no state ref")
	}

	state, ok := states[test.State.StateRef]
	if !ok {
		return resolvedTest{}, eb.Errorf("invalid tests data, can't find ovalstate ref")
	}

	if state.Evr.Datatype != "evr_string" {
		return resolvedTest{}, eb.With("data_type", state.Evr.Datatype).Wrapf(ErrNotSupported, "state data type")
	}

	// We don't currently support `greater than` operator
	if state.Evr.Operation == string(gt) {
		return resolvedTest{}, nil
	}

	if state.Evr.Operation != string(lte) && state.Evr.Operation != string(lt) {
		return resolvedTest{}, eb.With("operation", state.Evr.Operation).Wrapf(ErrNotSupported, "state operation")
	}

	return resolvedTest{
		Name:     pkgName,
		Version:  state.Evr.Text,
		Operator: operator(state.Evr.Operation),
	}, nil
}

func (vs VulnSrc) save(majorVer string, entries []Entry) error {
	eb := oops.With("major_version", majorVer)

	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		platformName := fmt.Sprintf(vs.platformFormat, majorVer)
		if err := vs.dbc.PutDataSource(tx, platformName, vs.source); err != nil {
			return eb.Wrapf(err, "failed to put data source")
		}

		if err := vs.commit(tx, platformName, entries); err != nil {
			return eb.Wrapf(err, "failed to commit entries")
		}
		return nil
	})
	if err != nil {
		return eb.Wrapf(err, "batch update failed")
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, platformName string, entries []Entry) error {
	for _, entry := range entries {
		cveID := entry.Metadata.Reference.RefID
		advisory := types.Advisory{}

		// Definition.Metadata.Patchable has a bool and "Not Applicable" string.
		patchable := strings.ToLower(entry.Metadata.Patchable)
		if patchable == "true" {
			advisory.FixedVersion = entry.Version
		} else if patchable == "not applicable" {
			continue
		}

		if err := vs.dbc.PutAdvisoryDetail(tx, cveID, entry.PkgName, []string{platformName}, advisory); err != nil {
			return oops.Wrapf(err, "failed to save advisory detail")
		}

		severity, _ := types.NewSeverity(strings.ToUpper(entry.Metadata.Severity))
		vuln := types.VulnerabilityDetail{
			Severity:    severity,
			Title:       entry.Metadata.Title,
			Description: entry.Metadata.Description,
			References:  []string{entry.Metadata.Reference.RefURL},
		}
		if err := vs.dbc.PutVulnerabilityDetail(tx, cveID, vs.source.ID, vuln); err != nil {
			return oops.Wrapf(err, "failed to save vulnerability detail")
		}

		if err := vs.dbc.PutVulnerabilityID(tx, cveID); err != nil {
			return oops.Wrapf(err, "failed to save the vulnerability ID")
		}
	}
	return nil
}

func (vs VulnSrc) Get(release, pkgName string) ([]types.Advisory, error) {
	eb := oops.In(string(vs.source.ID)).With("release", release).With("package_name", pkgName)
	bucket := fmt.Sprintf(vs.platformFormat, release)
	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get advisories")
	}
	return advisories, nil
}
