package corpus

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

type Entry struct {
	Data       []byte
	Hash       string
	Source     string
	Depth      int
	HitCount   int
	IsMinimal  bool
}

type Corpus struct {
	entries    []*Entry
	hashIndex  map[string]bool
	coverageMap map[uint64]bool
	mu         sync.RWMutex
	dir        string
	maxSize    int
}

func New(dir string, maxSize int) *Corpus {
	if maxSize <= 0 {
		maxSize = 4096
	}
	return &Corpus{
		hashIndex:   make(map[string]bool),
		coverageMap: make(map[uint64]bool),
		dir:         dir,
		maxSize:     maxSize,
	}
}

func (c *Corpus) Add(data []byte, source string, depth int) bool {
	hash := hashBytes(data)

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.hashIndex[hash] {
		return false
	}

	entry := &Entry{
		Data:   append([]byte(nil), data...),
		Hash:   hash,
		Source: source,
		Depth:  depth,
	}

	c.entries = append(c.entries, entry)
	c.hashIndex[hash] = true

	if len(c.entries) > c.maxSize {
		c.evict()
	}

	return true
}

func (c *Corpus) AddWithCoverage(data []byte, source string, depth int, coverageHash uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.coverageMap[coverageHash] {
		hash := hashBytes(data)
		if c.hashIndex[hash] {
			return false
		}
		for _, e := range c.entries {
			if e.Hash == hash {
				e.HitCount++
				return false
			}
		}
	}

	hash := hashBytes(data)
	if c.hashIndex[hash] {
		return false
	}

	c.coverageMap[coverageHash] = true

	entry := &Entry{
		Data:   append([]byte(nil), data...),
		Hash:   hash,
		Source: source,
		Depth:  depth,
	}

	c.entries = append(c.entries, entry)
	c.hashIndex[hash] = true

	if len(c.entries) > c.maxSize {
		c.evict()
	}

	return true
}

func (c *Corpus) Get(index int) []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if index < 0 || index >= len(c.entries) {
		return nil
	}

	entry := c.entries[index]
	entry.HitCount++
	result := make([]byte, len(entry.Data))
	copy(result, entry.Data)
	return result
}

func (c *Corpus) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

func (c *Corpus) CoverageCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.coverageMap)
}

func (c *Corpus) Save() error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.dir == "" {
		return nil
	}

	corpusDir := filepath.Join(c.dir, "corpus")
	if err := os.MkdirAll(corpusDir, 0750); err != nil {
		return fmt.Errorf("create corpus dir: %w", err)
	}

	for _, entry := range c.entries {
		path := filepath.Join(corpusDir, entry.Hash+".bin")
		if err := os.WriteFile(path, entry.Data, 0640); err != nil {
			log.Printf("warning: failed to save corpus entry %s: %v", entry.Hash[:8], err)
		}
	}

	log.Printf("saved %d corpus entries to %s", len(c.entries), corpusDir)
	return nil
}

func (c *Corpus) Load(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read corpus dir: %w", err)
	}

	loaded := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		if c.Add(data, "loaded:"+e.Name(), 0) {
			loaded++
		}
	}

	log.Printf("loaded %d corpus entries from %s", loaded, dir)
	return nil
}

func (c *Corpus) Minimize() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	before := len(c.entries)

	sort.Slice(c.entries, func(i, j int) bool {
		return len(c.entries[i].Data) < len(c.entries[j].Data)
	})

	seen := make(map[string]bool)
	var kept []*Entry
	for _, e := range c.entries {
		sig := responseSignature(e.Data)
		if !seen[sig] {
			seen[sig] = true
			e.IsMinimal = true
			kept = append(kept, e)
		}
	}

	c.entries = kept
	c.hashIndex = make(map[string]bool)
	for _, e := range c.entries {
		c.hashIndex[e.Hash] = true
	}

	removed := before - len(c.entries)
	if removed > 0 {
		log.Printf("corpus minimized: %d -> %d entries (%d removed)", before, len(c.entries), removed)
	}
	return removed
}

func (c *Corpus) evict() {
	sort.Slice(c.entries, func(i, j int) bool {
		return c.entries[i].HitCount > c.entries[j].HitCount
	})

	evicted := c.entries[len(c.entries)-1]
	c.entries = c.entries[:len(c.entries)-1]
	delete(c.hashIndex, evicted.Hash)
}

func hashBytes(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func responseSignature(data []byte) string {
	if len(data) <= 16 {
		return hashBytes(data)[:16]
	}
	prefix := data[:8]
	suffix := data[len(data)-8:]
	combined := append(prefix, suffix...)
	combined = append(combined, byte(len(data)>>8), byte(len(data)))
	return hashBytes(combined)[:16]
}
