package alpine

import (
	"encoding/json"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
	"log"
	"os"
	"path/filepath"
	"time"
)

const (
	osName  = "alpine"
	eolDir  = "eol"
	eolFile = "alpine.json"
)

type EolSrc struct {
	dbc db.Operation
}

func NewEolSrc() EolSrc {
	return EolSrc{
		dbc: db.Config{},
	}
}

func (es EolSrc) Name() types.SourceID {
	return vulnerability.AlpineEOL
}

func (es EolSrc) Update(dir string) (err error) {
	rootFilePath := filepath.Join(dir, "vuln-list", eolDir, osName, eolFile)
	var eolDates map[string]time.Time

	f, err := os.ReadFile(rootFilePath)
	if err != nil {
		return xerrors.Errorf("failed to open %q file", rootFilePath)
	}

	if err := json.Unmarshal(f, &eolDates); err != nil {
		return xerrors.Errorf("failed to decode list of end-of-life dates: %w", err)
	}

	return es.save(eolDates)
}

func (es EolSrc) save(eolDates map[string]time.Time) error {
	log.Println("Alpine EOL batch update")
	err := es.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		return es.commit(tx, eolDates)
	})
	if err != nil {
		return xerrors.Errorf("error in batch update: %w", err)
	}
	return nil
}

func (es EolSrc) commit(tx *bolt.Tx, eolDates map[string]time.Time) error {
	if err := es.dbc.PutEndOfLifeDates(tx, osName, eolDates); err != nil {
		return xerrors.Errorf("failed to save Alpine EOL dates: %w", err)
	}
	return nil
}
