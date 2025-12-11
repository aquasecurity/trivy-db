# Advisory Overrides

This directory contains override patches for vulnerability advisories. Patches are applied at file read time during database build without modifying the original cached files.

## Usage

By default, the `trivy-db build` command reads overrides from the `overrides/` directory:

```bash
trivy-db build --cache-dir /path/to/cache
```

To use a different directory:

```bash
trivy-db build --cache-dir /path/to/cache --overrides /path/to/overrides
```

## Use Cases

1. **ID remapping** - Add CVE-ID alias to GHSA-only advisories, making CVE the primary key
2. **Delete** - Remove false positive or unnecessary advisories
3. **Add references** - Add reference URLs to existing advisories

## Why jd Format?

We use [jd](https://github.com/josephburnett/jd) diff format instead of JSON Patch (RFC 6902) or JSON Merge Patch (RFC 7396):

| Format | Pros | Cons |
|--------|------|------|
| **JSON Patch** | Standard RFC 6902 | Not intuitive, verbose syntax |
| **JSON Merge Patch** | Simple for replacements | Cannot add/remove individual array elements, difficult to reject entire advisory, limited extensibility |
| **jd format** | Human-readable, flexible, can generate diffs for any change including file deletion | Non-standard |

The jd format is human-readable and offers high flexibility. It can handle any JSON transformation including adding/removing array elements and generating diffs that effectively delete entire files.

## Directory Structure

```
overrides/
  config.yaml           # Patch configuration
  patches/              # jd diff files
    GHSA-xxxx.jd
    CVE-yyyy-alpine.jd  # Include source name to avoid conflicts
```

## Configuration

### config.yaml

```yaml
patches:
  # Add CVE alias to GHSA advisory
  - target: /ghsa/advisories/github-reviewed/2025/12/GHSA-9qr9-h5gf-34mp/GHSA-9qr9-h5gf-34mp.json
    diff: patches/GHSA-9qr9-h5gf-34mp.jd

  # Delete false positive
  - target: /osv/go/example/CVE-2024-0000.json
    diff: patches/CVE-2024-0000-osv-go.jd
```

**Note:** `target` must start with `/` to ensure proper path boundary matching.

## Creating Diff Files

Install jd v2.3.0 (this is the version used by the library):

```bash
go install github.com/josephburnett/jd/v2/jd@v2.3.0
```

**Note:** The Homebrew version may be outdated (v1.x), which generates incompatible diff formats.

### Generate diff from two files

```bash
# Create diff between original and modified JSON
jd original.json modified.json > patch.jd

# Test applying the diff
jd -p patch.jd original.json

# For set semantics (prevents duplicates), use -set
jd -set original.json modified.json > patch.jd
```

### Common patterns

**Add element to array (as set - recommended for aliases):**
```
@ ["aliases",{}]
+ "CVE-2024-12345"
```

The `{}` indicates set semantics, which prevents duplicates if the element already exists.

**Add element to array (append to end):**
```
@ ["aliases",-1]
+ "CVE-2024-12345"
```

Note: This will add duplicates if the element already exists. Use set semantics (`{}`) when possible.

**Add new field:**
```
@ ["references"]
+ [{"type":"ADVISORY","url":"https://example.invalid"}]
```

**Delete entire file** (generates empty output, file will be skipped):
```bash
# Diff against empty object or /dev/null
jd original.json /dev/null > delete.jd
```

Example delete diff (keys are sorted alphabetically):
```
@ []
- {"aliases":[],"id":"GHSA-xxxx"}
```

## Verification

After adding a new override, build the database and verify:

```bash
# Build with overrides
./trivy-db build --cache-dir /path/to/cache --output-dir /tmp/test-db --only-update ghsa

# Check the result using bbolt
bbolt keys /tmp/test-db/trivy.db "npm::GitHub Security Advisory npm" "next"
```

## Important Notes

### Overrides are Temporary

Overrides are intended as temporary fixes until upstream sources are corrected. When the upstream advisory is updated:

- **If the fix matches our override**: Remove the override to avoid duplication or conflicts
- **If the upstream changes differently**: Update or remove the override as needed

Periodically review overrides to ensure they are still necessary.

## Design Decisions

### Path Suffix Matching

We use path suffix matching (e.g., `/ghsa/.../GHSA-xxxx.json`) rather than exact path matching because:

- Cache directory path is not available at the matching layer
- Does not require changes to `FileWalk` interface

### Performance

Performance overhead is negligible:

| Build | Time | Overhead |
|-------|------|----------|
| GHSA only | ~1.3s | - |
| Full build | ~3.1s | ~1.2% |

In the future, we may pass `cache-dir` to enable exact path matching for better precision.
