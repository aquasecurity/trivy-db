package override

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/josephburnett/jd/v2"
	"github.com/samber/oops"
	"gopkg.in/yaml.v3"
)

// Config represents the override configuration file
type Config struct {
	Patches []PatchEntry `yaml:"patches"`
}

// PatchEntry represents a single patch entry
type PatchEntry struct {
	Target string `yaml:"target"` // Path suffix to match (e.g., "ghsa/2025/11/GHSA-xxxx.json")
	Diff   string `yaml:"diff"`   // Path to jd diff file (relative to overrides dir)
}

// Patches holds loaded override configuration
type Patches struct {
	entries      []patchEntry
	overridesDir string
}

type patchEntry struct {
	pathSuffix string
	diffFile   string // Path to diff file (relative to overrides dir)
}

// Patch represents a matched patch that can be applied to content
type Patch struct {
	diff jd.Diff
}

// Load reads config.yaml from the given directory
func Load(overridesDir string) (*Patches, error) {
	eb := oops.With("overrides_dir", overridesDir)

	configPath := filepath.Join(overridesDir, "config.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to read config file")
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, eb.Wrapf(err, "failed to parse config.yaml")
	}

	patches := &Patches{
		entries:      make([]patchEntry, 0, len(cfg.Patches)),
		overridesDir: overridesDir,
	}

	for _, p := range cfg.Patches {
		eb = eb.With("target", p.Target, "diff", p.Diff)
		if p.Diff == "" {
			return nil, eb.Errorf("patch entry missing 'diff' field")
		} else if !filepath.IsLocal(p.Diff) {
			return nil, eb.Errorf("diff path must be local")
		}

		target := filepath.ToSlash(p.Target) // Normalize to forward slashes
		if !strings.HasPrefix(target, "/") {
			return nil, eb.Errorf("target path must start with '/'")
		}

		entry := patchEntry{
			pathSuffix: target,
			diffFile:   p.Diff,
		}

		patches.entries = append(patches.entries, entry)
	}

	return patches, nil
}

// Match checks if any patch matches the given path.
// Returns (patch, true) if a match is found, (nil, false) otherwise.
// The diff file is read when a match is found.
func (p *Patches) Match(path string) (*Patch, bool, error) {
	if p == nil {
		return nil, false, nil
	}

	normalizedPath := filepath.ToSlash(path)
	for _, entry := range p.entries {
		if !hasSuffix(normalizedPath, entry.pathSuffix) {
			continue
		}

		// Read and parse diff file when matched
		diffPath := filepath.Join(p.overridesDir, entry.diffFile)
		diffData, err := os.ReadFile(diffPath)
		if err != nil {
			return nil, false, oops.With("diff_file", diffPath).Wrapf(err, "failed to read diff file")
		}

		diff, err := jd.ReadDiffString(string(diffData))
		if err != nil {
			return nil, false, oops.With("diff_file", diffPath).Wrapf(err, "failed to parse diff file")
		}

		return &Patch{diff: diff}, true, nil
	}

	return nil, false, nil
}

// Apply applies the patch to the original content.
// Returns:
//   - ([]byte{}, nil) if the file should be deleted (empty result)
//   - (patched, nil) if the patch was applied successfully
func (p *Patch) Apply(original []byte) ([]byte, error) {
	node, err := jd.ReadJsonString(string(original))
	if err != nil {
		return nil, oops.Wrapf(err, "failed to parse original JSON")
	}

	patched, err := node.Patch(p.diff)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to apply patch")
	}

	return []byte(patched.Json()), nil
}

// Count returns the number of patch entries
func (p *Patches) Count() int {
	if p == nil {
		return 0
	}
	return len(p.entries)
}

// hasSuffix checks if path ends with suffix, ensuring proper path boundary.
// The suffix must start with '/' to ensure path boundary matching.
// e.g., "/foo/bar.json" matches "/bar.json" but not "ar.json"
func hasSuffix(path, suffix string) bool {
	if len(path) < len(suffix) {
		return false
	}
	return strings.HasSuffix(path, suffix)
}
