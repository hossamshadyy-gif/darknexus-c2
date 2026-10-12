package engine

import (
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/darknexus/fuzzer/internal/capture"
	"github.com/darknexus/fuzzer/internal/config"
	"github.com/darknexus/fuzzer/internal/corpus"
	"github.com/darknexus/fuzzer/internal/dedup"
	"github.com/darknexus/fuzzer/internal/generator"
	"github.com/darknexus/fuzzer/internal/monitor"
	"github.com/darknexus/fuzzer/internal/mutator"
	"github.com/darknexus/fuzzer/internal/reporter"
	"github.com/darknexus/fuzzer/internal/transport"
)

type Stats struct {
	Iterations    atomic.Int64
	Findings      atomic.Int64
	UniqueFindings atomic.Int64
	ConnErrors    atomic.Int64
	Timeouts      atomic.Int64
	Responses     atomic.Int64
	CorpusSize    atomic.Int64
	CoveragePaths atomic.Int64
	StartTime     time.Time
}

type Engine struct {
	cfg       *config.FuzzerConfig
	transport transport.Transport
	mutator   *mutator.Mutator
	monitor   *monitor.Monitor
	reporter  *reporter.Reporter
	corpus    *corpus.Corpus
	dedup     *dedup.Deduplicator
	capturer  *capture.Capturer
	generator *generator.Generator
	seeds     [][]byte
	stats     Stats
	findings  []*monitor.Finding
	mu        sync.Mutex
	stopCh    chan struct{}
	stopped   atomic.Bool
}

func New(
	cfg *config.FuzzerConfig,
	trans transport.Transport,
	mut *mutator.Mutator,
	mon *monitor.Monitor,
	rep *reporter.Reporter,
	seeds [][]byte,
) *Engine {
	e := &Engine{
		cfg:       cfg,
		transport: trans,
		mutator:   mut,
		monitor:   mon,
		reporter:  rep,
		seeds:     seeds,
		corpus:    corpus.New(cfg.OutputDir, 4096),
		dedup:     dedup.New(),
		capturer:  capture.New(cfg.EnablePCAP, 100000),
		generator: generator.New(),
		stopCh:    make(chan struct{}),
	}

	for _, seed := range seeds {
		e.corpus.Add(seed, "seed", 0)
	}

	e.generator.AddGrammar(generator.DNSQueryGrammar())
	e.generator.AddGrammar(generator.HTTPRequestGrammar())

	return e
}

func (e *Engine) Run() error {
	e.stats.StartTime = time.Now()

	if e.cfg.Profile != nil {
		e.applyProfile()
	}

	var wg sync.WaitGroup
	workCh := make(chan int, e.cfg.Workers*2)

	for i := 0; i < e.cfg.Workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			e.worker(workerID, workCh)
		}(i)
	}

	go func() {
		for i := 0; i < e.cfg.Iterations; i++ {
			select {
			case <-e.stopCh:
				close(workCh)
				return
			case workCh <- i:
			}
		}
		close(workCh)
	}()

	go e.progressReporter()

	wg.Wait()

	return e.finalize()
}

func (e *Engine) Stop() {
	if e.stopped.CompareAndSwap(false, true) {
		close(e.stopCh)
	}
}

func (e *Engine) worker(id int, work <-chan int) {
	for iteration := range work {
		if e.stopped.Load() {
			return
		}

		var input []byte
		var strategyName string

		corpusSize := e.corpus.Size()
		if corpusSize > 0 && iteration%5 != 0 {
			seed := e.corpus.Get(iteration % corpusSize)
			if seed != nil {
				mutated, strategy := e.mutator.Mutate(seed)
				input = mutated
				strategyName = strategy.String()
			}
		}

		if input == nil {
			grammarName := e.pickGrammar()
			if grammarName != "" && iteration%10 == 0 {
				generated, fieldName, err := e.generator.GenerateFuzzed(grammarName)
				if err == nil {
					input = generated
					strategyName = "grammar:" + fieldName
				}
			}
		}

		if input == nil {
			seed := e.seeds[iteration%len(e.seeds)]
			mutated, strategy := e.mutator.Mutate(seed)
			input = mutated
			strategyName = strategy.String()
		}

		if e.capturer != nil {
			e.capturer.Record(&capture.Packet{
				Timestamp: time.Now(),
				Direction: capture.DirSend,
				Data:      input,
				SrcPort:   uint16(40000 + (iteration % 25535)),
				DstPort:   uint16(e.cfg.Port),
				Iteration: iteration,
				Strategy:  strategyName,
			})
		}

		resp := e.transport.Send(input)
		e.stats.Iterations.Add(1)

		if resp.ConnErr {
			e.stats.ConnErrors.Add(1)
		} else if resp.Data == nil {
			e.stats.Timeouts.Add(1)
		} else {
			e.stats.Responses.Add(1)

			if e.capturer != nil {
				e.capturer.Record(&capture.Packet{
					Timestamp: time.Now(),
					Direction: capture.DirRecv,
					Data:      resp.Data,
					SrcPort:   uint16(e.cfg.Port),
					DstPort:   uint16(40000 + (iteration % 25535)),
					Iteration: iteration,
				})
			}

			coverageHash := computeCoverageHash(resp.Data, resp.Duration)
			if e.corpus.AddWithCoverage(input, strategyName, 1, coverageHash) {
				e.stats.CoveragePaths.Add(1)
				e.stats.CorpusSize.Store(int64(e.corpus.Size()))
				if e.cfg.Verbose {
					log.Printf("[corpus] new coverage path at iteration %d (corpus: %d, coverage: %d)",
						iteration, e.corpus.Size(), e.corpus.CoverageCount())
				}
			}
		}

		finding := e.monitor.Analyze(resp, input, strategyName, iteration)
		if finding != nil {
			finding.InputHex = hex.EncodeToString(input)

			isNew, group := e.dedup.Add(finding)

			e.mu.Lock()
			e.findings = append(e.findings, finding)
			e.mu.Unlock()
			e.stats.Findings.Add(1)

			if isNew {
				e.stats.UniqueFindings.Add(1)
				log.Printf("[!] NEW FINDING #%d [%s] %s (iteration %d, strategy: %s)",
					finding.ID, finding.Severity, finding.Type, iteration, strategyName)
			} else if e.cfg.Verbose {
				log.Printf("[*] duplicate finding (group %s, %d total) at iteration %d",
					group.Signature[:8], len(group.Findings), iteration)
			}

			if e.cfg.Verbose {
				log.Printf("    input (%d bytes): %s", len(input), finding.InputHex)
			}
		}

		if e.cfg.Delay > 0 {
			time.Sleep(e.cfg.Delay)
		}
	}
}

func (e *Engine) pickGrammar() string {
	switch e.cfg.Protocol {
	case "udp":
		return "dns_query"
	case "tcp", "tls":
		return "http_request"
	default:
		return ""
	}
}

func (e *Engine) progressReporter() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			iters := e.stats.Iterations.Load()
			elapsed := time.Since(e.stats.StartTime)
			rate := float64(iters) / elapsed.Seconds()
			remaining := int64(0)
			if rate > 0 {
				remaining = int64(float64(int64(e.cfg.Iterations)-iters) / rate)
			}
			eta := time.Duration(remaining) * time.Second

			log.Printf("progress: %d/%d (%.1f/sec) ETA %s | unique: %d total: %d | corpus: %d coverage: %d | errs: %d timeouts: %d",
				iters, e.cfg.Iterations, rate, eta.Round(time.Second),
				e.stats.UniqueFindings.Load(), e.stats.Findings.Load(),
				e.stats.CorpusSize.Load(), e.stats.CoveragePaths.Load(),
				e.stats.ConnErrors.Load(), e.stats.Timeouts.Load())
		}
	}
}

func (e *Engine) finalize() error {
	elapsed := time.Since(e.stats.StartTime)
	iters := e.stats.Iterations.Load()

	log.Println("=== Fuzzing Complete ===")
	log.Printf("duration: %s", elapsed.Round(time.Millisecond))
	log.Printf("iterations: %d (%.1f/sec)", iters, float64(iters)/elapsed.Seconds())
	log.Printf("unique findings: %d (total: %d)", e.stats.UniqueFindings.Load(), e.stats.Findings.Load())
	log.Printf("corpus size: %d | coverage paths: %d", e.corpus.Size(), e.corpus.CoverageCount())
	log.Printf("connection errors: %d | timeouts: %d | responses: %d",
		e.stats.ConnErrors.Load(), e.stats.Timeouts.Load(), e.stats.Responses.Load())

	if e.dedup.UniqueCount() > 0 {
		log.Println("\n" + e.dedup.Summary())
	}

	if err := e.corpus.Save(); err != nil {
		log.Printf("warning: failed to save corpus: %v", err)
	}

	if e.cfg.EnablePCAP {
		if err := e.capturer.WritePCAP(e.cfg.OutputDir); err != nil {
			log.Printf("warning: failed to write PCAP: %v", err)
		}
	}

	e.mu.Lock()
	findings := make([]*monitor.Finding, len(e.findings))
	copy(findings, e.findings)
	e.mu.Unlock()

	if len(findings) > 0 {
		report := &reporter.Report{
			Target:        fmt.Sprintf("%s:%d", e.cfg.Host, e.cfg.Port),
			Protocol:      e.cfg.Protocol,
			StartTime:     e.stats.StartTime,
			EndTime:       time.Now(),
			Duration:      elapsed,
			Iterations:    iters,
			Findings:      findings,
			UniqueFindings: e.dedup.UniqueCount(),
			ConnErrors:    e.stats.ConnErrors.Load(),
			Timeouts:      e.stats.Timeouts.Load(),
			Responses:     e.stats.Responses.Load(),
			CorpusSize:    int64(e.corpus.Size()),
			CoveragePaths: e.stats.CoveragePaths.Load(),
		}
		return e.reporter.Write(report)
	}

	log.Println("no findings to report")
	return nil
}

func (e *Engine) applyProfile() {
	if e.cfg.Profile.Mutation.Dictionary != nil {
		e.mutator.SetDictionary(e.cfg.Profile.Mutation.Dictionary)
	}
	if e.cfg.Profile.Monitor.CrashPatterns != nil {
		e.monitor.SetCrashPatterns(e.cfg.Profile.Monitor.CrashPatterns)
	}
	if e.cfg.Profile.Monitor.ErrorPatterns != nil {
		e.monitor.SetErrorPatterns(e.cfg.Profile.Monitor.ErrorPatterns)
	}
}

func computeCoverageHash(response []byte, duration time.Duration) uint64 {
	h := fnv.New64a()

	sizeClass := byte(0)
	switch {
	case len(response) > 10000:
		sizeClass = 4
	case len(response) > 1000:
		sizeClass = 3
	case len(response) > 100:
		sizeClass = 2
	case len(response) > 10:
		sizeClass = 1
	}
	h.Write([]byte{sizeClass})

	if len(response) >= 4 {
		h.Write(response[:4])
	}

	durationClass := byte(0)
	switch {
	case duration > 5*time.Second:
		durationClass = 3
	case duration > 1*time.Second:
		durationClass = 2
	case duration > 100*time.Millisecond:
		durationClass = 1
	}
	h.Write([]byte{durationClass})

	return h.Sum64()
}
