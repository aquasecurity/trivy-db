package redhatcsaf

import (
	"fmt"
	"log"
	"slices"
	"sort"
	"strings"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/samber/lo"
	"github.com/samber/oops"

	"github.com/aquasecurity/trivy-db/pkg/types"
)

type Aggregator struct{}

// AggregateEntries aggregates raw entries through multiple stages:
// 1. Aggregate CVEs (merge entries that only differ in CVE-ID and severity)
// 2. Aggregate architectures (merge entries that only differ in arch)
// 3. Aggregate CPEs (merge entries that only differ in CPE)
func (a *Aggregator) AggregateEntries(rawEntries RawEntries) (Entries, error) {
	// Stage 1: Merge CVEs
	entriesWithMergedCVEs, err := a.aggregateCVEs(rawEntries)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to aggregate CVEs")
	}

	// Stage 2: Merge architectures
	entriesWithMergedArches := a.aggregateArches(entriesWithMergedCVEs)

	// Stage 3: Merge CPEs
	finalEntries := a.aggregateCPEs(entriesWithMergedArches)

	return finalEntries, nil
}

// aggregateCVEs merges entries that only differ in their CVE IDs (Alias)
func (a *Aggregator) aggregateCVEs(entries RawEntries) (Entries, error) {
	// Define key structure for aggregation
	type groupKey struct {
		FixedVersion string
		Status       types.Status
		Arch         string
		CPE          csaf.CPE
	}

	// Group by everything except Alias and Severity
	groups := lo.GroupBy(entries, func(e RawEntry) groupKey {
		return groupKey{
			FixedVersion: e.FixedVersion,
			Status:       e.Status,
			Arch:         e.Arch,
			CPE:          e.CPE,
		}
	})

	var result Entries
	for key, group := range groups {
		eb := oops.With("fixed_version", key.FixedVersion).With("status", key.Status.String()).
			With("arch", key.Arch).With("cpe", key.CPE)

		// Create CVE entries
		cves := lo.Map(group, func(e RawEntry, _ int) CVEEntry {
			return CVEEntry{
				ID:       string(e.Alias),
				Severity: e.Severity,
			}
		})

		// Sort CVEs for consistency
		slices.SortFunc(cves, func(a, b CVEEntry) int {
			return strings.Compare(a.ID, b.ID)
		})

		// CVEs should not be duplicated
		if duplicated := lo.FindDuplicatesBy(cves, func(cve CVEEntry) string { return cve.ID }); len(duplicated) != 0 {
			return nil, eb.With("entry_num", len(entries)).With("cve_num", len(cves)).
				With("duplicated", duplicated).Wrapf(errUnexpectedRecord, "duplicated CVEs found")
		}

		// Create entry using common fields
		result = append(result, Entry{
			FixedVersion:    key.FixedVersion,
			Status:          key.Status,
			Arches:          []string{key.Arch},
			AffectedCPEList: []string{string(key.CPE)},
			CVEs:            cves,
		})
	}

	return result, nil
}

// aggregateArches merges entries that only differ in their architecture
func (a *Aggregator) aggregateArches(entries Entries) Entries {
	// Define key structure for aggregation
	type groupKey struct {
		FixedVersion string
		Status       types.Status
		CVEs         string // String representation of sorted CVEs to make it comparable
		CPE          string
	}

	// Group by everything except architectures
	groups := lo.GroupBy(entries, func(e Entry) groupKey {
		return groupKey{
			FixedVersion: e.FixedVersion,
			Status:       e.Status,
			CVEs:         encodeCVEs(e.CVEs),
			CPE:          e.AffectedCPEList[0], // At this stage, each entry has exactly one CPE
		}
	})

	var result Entries
	for key, group := range groups {
		// Collect unique architectures
		archSet := NewOrderedSet[string]()
		for _, entry := range group {
			// Filter out empty arches
			arches := lo.Filter(entry.Arches, func(arch string, _ int) bool {
				return arch != ""
			})
			archSet.Append(arches...)
		}

		// Create new entry with merged architectures
		result = append(result, Entry{
			FixedVersion:    key.FixedVersion,
			Status:          key.Status,
			CVEs:            decodeCVEs(key.CVEs),
			AffectedCPEList: []string{key.CPE},
			Arches:          archSet.Values(), // Get sorted slice of architectures
		})
	}

	return result
}

// aggregateCPEs merges entries that only differ in their CPEs
func (a *Aggregator) aggregateCPEs(entries Entries) Entries {
	// Define key structure for aggregation
	type groupKey struct {
		FixedVersion string
		Status       types.Status
		CVEs         string // String representation of sorted CVEs
		Arches       string // String representation of sorted architectures
	}

	// Group by everything except CPEs
	groups := lo.GroupBy(entries, func(e Entry) groupKey {
		return groupKey{
			FixedVersion: e.FixedVersion,
			Status:       e.Status,
			CVEs:         encodeCVEs(e.CVEs),
			Arches:       encodeArches(e.Arches),
		}
	})

	var result Entries
	for key, group := range groups {
		// Collect unique CPEs
		cpeSet := NewOrderedSet[string]()
		for _, entry := range group {
			cpeSet.Append(entry.AffectedCPEList...)
		}

		// Create new entry with merged CPEs
		result = append(result, Entry{
			FixedVersion:    key.FixedVersion,
			Status:          key.Status,
			CVEs:            decodeCVEs(key.CVEs),
			Arches:          decodeArches(key.Arches),
			AffectedCPEList: cpeSet.Values(), // Get sorted slice of CPEs
		})
	}

	sort.Sort(result)
	return result
}

// encodeCVEs creates a consistent string representation of CVE entries
// Format: "id1:severity1|id2:severity2|..."
// The CVE entries are already sorted by ID.
func encodeCVEs(cves []CVEEntry) string {
	entries := lo.Map(cves, func(cve CVEEntry, _ int) string {
		return fmt.Sprintf("%s:%s", cve.ID, cve.Severity)
	})
	return strings.Join(entries, "|")
}

// decodeCVEs decodes a string representation of CVE entries
func decodeCVEs(encoded string) []CVEEntry {
	if encoded == "" {
		return nil
	}

	return lo.FilterMap(strings.Split(encoded, "|"), func(entry string, _ int) (CVEEntry, bool) {
		// Split ID and severity
		id, severityStr, found := strings.Cut(entry, ":")
		if !found {
			log.Printf("Invalid encoded string: %q", entry)
			return CVEEntry{}, false
		}

		// Parse severity
		severity, err := types.NewSeverity(severityStr)
		if err != nil {
			log.Printf("Failed to parse severity for CVE %q: %v", id, err)
			return CVEEntry{}, false
		}

		return CVEEntry{
			ID:       id,
			Severity: severity,
		}, true
	})
}

// encodeArches encodes a slice of architectures as a string for consistent grouping
func encodeArches(arches []string) string {
	return strings.Join(arches, "|")
}

func decodeArches(encoded string) []string {
	if encoded == "" {
		return nil
	}
	return strings.Split(encoded, "|")
}
