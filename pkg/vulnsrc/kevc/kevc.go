package kevc

import (
	"encoding/json"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
	"io"
	"path/filepath"
	"time"
)

var (
	kevcDir = filepath.Join("kevc")
	source  = types.DataSource{
		ID:   vulnerability.KnownExploitedVulnerabilityCatalog,
		Name: "Known Exploited Vulnerability Catalog",
		URL:  "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
	}
)

const (
	platformName = "Known Exploited Vulnerability Catalog"
	DateFormat   = "2006-01-02"
)

type Exploitable struct {
	CveID          string
	DateAdded      Time
	Description    string `json:"shortDescription"`
	RequiredAction string
	DueDate        Time
}

type VulnSrc struct {
	dbc db.Operation
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Name() types.SourceID {
	return source.ID
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", kevcDir)

	var exploitables []Exploitable
	err := utils.FileWalk(rootDir, func(r io.Reader, path string) error {
		var e Exploitable
		if err := json.NewDecoder(r).Decode(&e); err != nil {
			return xerrors.Errorf("failed to decode json: %w", err)
		}
		exploitables = append(exploitables, e)
		return nil
	})

	if err != nil {
		return xerrors.Errorf("failed to walk file: %w", err)
	}
	if err := vs.save(exploitables); err != nil {
		return xerrors.Errorf("failed to save exploitable: %w", err)
	}

	return nil
}

func (vs VulnSrc) save(exploitables []Exploitable) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		if err := vs.dbc.PutDataSource(tx, platformName, source); err != nil {
			return xerrors.Errorf("failed to put data source: %w", err)
		}

		if err := vs.commit(tx, exploitables); err != nil {
			return xerrors.Errorf("")
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in db batch update: %w", err)
	}

	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, exploitables []Exploitable) error {
	for _, exploitable := range exploitables {
		e := types.VulnerabilityExploitable{
			DataSource:     &source,
			DateAdded:      &exploitable.DateAdded.Time,
			Description:    exploitable.Description,
			RequiredAction: exploitable.RequiredAction,
			DueDate:        &exploitable.DueDate.Time,
		}

		if err := vs.dbc.PutVulnerabilityID(tx, exploitable.CveID); err != nil {
			return xerrors.Errorf("failed to put Known Exploited Vulnerability ID: %w", err)
		}

		if err := vs.dbc.PutVulnerabilityExploitable(tx, exploitable.CveID, source.ID, e); err != nil {
			return xerrors.Errorf("failed to save Known Exploited vulnerability Catalog: %w", err)
		}
	}
	return nil
}

func (vs VulnSrc) Get(cveID string) (map[types.SourceID]types.VulnerabilityExploitable, error) {
	exploitables, err := vs.dbc.GetVulnerabilityExploitable(cveID)
	if err != nil {
		return nil, xerrors.Errorf("failed to get Known Exploited Vulnerability Catalog: %w", err)
	}
	return exploitables, nil
}

type Time struct {
	time.Time
}

func (date *Time) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		date.Time = time.Time{}
		return nil
	}

	var err error
	date.Time, err = time.Parse(`"`+DateFormat+`"`, string(b))
	if _, ok := err.(*time.ParseError); !ok {
		return err
	}
	date.Time, err = time.Parse(`"`+time.RFC3339+`"`, string(b))
	return err
}
