package override

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/josephburnett/jd/v2"
	"github.com/samber/oops"
	"go.yaml.in/yaml/v4"
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
	entries      []PatchEntry
	overridesDir string
}

// Patch represents a matched patch that can be applied to content
type Patch struct {
	diff jd.Diff
}

// Load reads config.yaml from the given directory
func Load(overridesDir string) (*Patches, error) {
	eb := oops.With("overrides_dir", overridesDir)

	configPath := filepath.Join(overridesDir, "config.yaml")
	f, err := os.Open(configPath)
	if err != nil {
		return nil, eb.Wrapf(err, "failed to open config file")
	}
	defer f.Close()

	var cfg Config
	if err := yaml.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, eb.Wrapf(err, "failed to parse config.yaml")
	}

	patches := &Patches{
		entries:      make([]PatchEntry, 0, len(cfg.Patches)),
		overridesDir: overridesDir,
	}

	for _, p := range cfg.Patches {
		eb := eb.With("target", p.Target, "diff", p.Diff)
		if p.Diff == "" {
			return nil, eb.Errorf("patch entry missing 'diff' field")
		} else if !filepath.IsLocal(p.Diff) {
			return nil, eb.Errorf("diff path must be local")
		}

		target := filepath.ToSlash(p.Target) // Normalize to forward slashes
		if !strings.HasPrefix(target, "/") {
			return nil, eb.Errorf("target path must start with '/'")
		}

		patches.entries = append(patches.entries, PatchEntry{
			Target: target,
			Diff:   p.Diff,
		})
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
		if !hasSuffix(normalizedPath, entry.Target) {
			continue
		}

		// Read and parse diff file when matched
		diffPath := filepath.Join(p.overridesDir, entry.Diff)
		diff, err := jd.ReadDiffFile(diffPath)
		if err != nil {
			return nil, false, oops.With("diff_file", diffPath).Wrapf(err, "failed to read/parse diff file")
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
