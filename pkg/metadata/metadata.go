package metadata

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/samber/oops"
)

const metadataFile = "metadata.json"

type Metadata struct {
	Version      int `json:",omitempty"`
	NextUpdate   time.Time
	UpdatedAt    time.Time
	DownloadedAt time.Time // This field will be filled after downloading.
}

// Client defines the file meta
type Client struct {
	filePath string
}

// NewClient is the factory method for the metadata Client
func NewClient(dbDir string) Client {
	return Client{
		filePath: Path(dbDir),
	}
}

func Path(dbDir string) string {
	return filepath.Join(dbDir, metadataFile)
}

// Get returns the file metadata
func (c Client) Get() (Metadata, error) {
	eb := oops.With("file_path", c.filePath)

	f, err := os.Open(c.filePath)
	if err != nil {
		return Metadata{}, eb.Wrapf(err, "file open error")
	}
	defer f.Close()

	var metadata Metadata
	if err = json.NewDecoder(f).Decode(&metadata); err != nil {
		return Metadata{}, eb.Wrapf(err, "json decode error")
	}
	return metadata, nil
}

func (c Client) Update(meta Metadata) error {
	eb := oops.With("file_path", c.filePath)

	if err := os.MkdirAll(filepath.Dir(c.filePath), 0o744); err != nil {
		return eb.Wrapf(err, "mkdir error")
	}

	f, err := os.Create(c.filePath)
	if err != nil {
		return eb.Wrapf(err, "file create error")
	}
	defer f.Close()

	if err = json.NewEncoder(f).Encode(&meta); err != nil {
		return eb.Wrapf(err, "json encode error")
	}
	return nil
}

// Delete deletes the file of database metadata
func (c Client) Delete() error {
	if err := os.Remove(c.filePath); err != nil {
		return oops.With("file_path", c.filePath).Wrapf(err, "file remove error")
	}
	return nil
}
