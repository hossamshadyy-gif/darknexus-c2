package dedup

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/darknexus/fuzzer/internal/monitor"
)

type CrashGroup struct {
	Signature string
	Type      string
	Severity  monitor.FindingSeverity
	Findings  []*monitor.Finding
	FirstSeen int
	LastSeen  int
}

type Deduplicator struct {
	groups map[string]*CrashGroup
	mu     sync.RWMutex
}

func New() *Deduplicator {
	return &Deduplicator{
		groups: make(map[string]*CrashGroup),
	}
}

func (d *Deduplicator) Add(finding *monitor.Finding) (isNew bool, group *CrashGroup) {
	sig := d.signature(finding)

	d.mu.Lock()
	defer d.mu.Unlock()

	existing, ok := d.groups[sig]
	if ok {
		existing.Findings = append(existing.Findings, finding)
		if finding.Iteration > existing.LastSeen {
			existing.LastSeen = finding.Iteration
		}
		return false, existing
	}

	group = &CrashGroup{
		Signature: sig,
		Type:      finding.Type,
		Severity:  finding.Severity,
		Findings:  []*monitor.Finding{finding},
		FirstSeen: finding.Iteration,
		LastSeen:  finding.Iteration,
	}
	d.groups[sig] = group
	return true, group
}

func (d *Deduplicator) Groups() []*CrashGroup {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var groups []*CrashGroup
	for _, g := range d.groups {
		groups = append(groups, g)
	}

	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Severity != groups[j].Severity {
			return groups[i].Severity > groups[j].Severity
		}
		return len(groups[i].Findings) > len(groups[j].Findings)
	})

	return groups
}

func (d *Deduplicator) UniqueCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.groups)
}

func (d *Deduplicator) TotalCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	total := 0
	for _, g := range d.groups {
		total += len(g.Findings)
	}
	return total
}

func (d *Deduplicator) Summary() string {
	groups := d.Groups()
	if len(groups) == 0 {
		return "no unique crashes"
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "%d unique crash signatures from %d total findings:\n", d.UniqueCount(), d.TotalCount())
	for i, g := range groups {
		fmt.Fprintf(&sb, "  [%d] %s (%s) - %d occurrences [iterations %d-%d]\n",
			i+1, g.Type, g.Severity, len(g.Findings), g.FirstSeen, g.LastSeen)

		if len(g.Findings) > 0 {
			smallest := g.Findings[0]
			for _, f := range g.Findings[1:] {
				if len(f.Input) < len(smallest.Input) {
					smallest = f
				}
			}
			fmt.Fprintf(&sb, "       smallest input: %d bytes (strategy: %s)\n",
				len(smallest.Input), smallest.Strategy)
		}
	}
	return sb.String()
}

func (d *Deduplicator) signature(finding *monitor.Finding) string {
	var parts []string

	parts = append(parts, finding.Type)

	if finding.Response != nil {
		respSig := responseSignature(finding.Response)
		parts = append(parts, respSig)
	}

	parts = append(parts, inputClassSignature(finding.Input))

	combined := strings.Join(parts, "|")
	h := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(h[:8])
}

func responseSignature(resp []byte) string {
	if len(resp) == 0 {
		return "empty"
	}

	lower := strings.ToLower(string(resp))

	keywords := []string{
		"segfault", "sigsegv", "sigabrt", "panic",
		"nil pointer", "null pointer", "stack overflow",
		"buffer overflow", "heap corruption",
		"access violation", "out of bounds",
	}

	var found []string
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			found = append(found, kw)
		}
	}

	if len(found) > 0 {
		sort.Strings(found)
		return strings.Join(found, "+")
	}

	sizeClass := "tiny"
	switch {
	case len(resp) > 10000:
		sizeClass = "huge"
	case len(resp) > 1000:
		sizeClass = "large"
	case len(resp) > 100:
		sizeClass = "medium"
	case len(resp) > 10:
		sizeClass = "small"
	}

	if len(resp) >= 3 {
		return fmt.Sprintf("%s:prefix=%x", sizeClass, resp[:3])
	}
	return sizeClass
}

func inputClassSignature(input []byte) string {
	sizeClass := "small"
	switch {
	case len(input) > 10000:
		sizeClass = "huge"
	case len(input) > 1000:
		sizeClass = "large"
	case len(input) > 100:
		sizeClass = "medium"
	}

	nullCount := 0
	printableCount := 0
	for _, b := range input {
		if b == 0 {
			nullCount++
		}
		if b >= 0x20 && b <= 0x7E {
			printableCount++
		}
	}

	contentType := "binary"
	if len(input) > 0 {
		ratio := float64(printableCount) / float64(len(input))
		if ratio > 0.8 {
			contentType = "text"
		} else if ratio > 0.4 {
			contentType = "mixed"
		}
	}

	return fmt.Sprintf("%s:%s", sizeClass, contentType)
}
