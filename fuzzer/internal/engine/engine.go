package engine

import (
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/darknexus/fuzzer/internal/config"
	"github.com/darknexus/fuzzer/internal/monitor"
	"github.com/darknexus/fuzzer/internal/mutator"
	"github.com/darknexus/fuzzer/internal/reporter"
	"github.com/darknexus/fuzzer/internal/transport"
)

type Stats struct {
	Iterations    atomic.Int64
	Findings      atomic.Int64
	ConnErrors    atomic.Int64
	Timeouts      atomic.Int64
	Responses     atomic.Int64
	StartTime     time.Time
}

type Engine struct {
	cfg       *config.FuzzerConfig
	transport transport.Transport
	mutator   *mutator.Mutator
	monitor   *monitor.Monitor
	reporter  *reporter.Reporter
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
	return &Engine{
		cfg:       cfg,
		transport: trans,
		mutator:   mut,
		monitor:   mon,
		reporter:  rep,
		seeds:     seeds,
		stopCh:    make(chan struct{}),
	}
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

		seed := e.seeds[iteration%len(e.seeds)]
		mutated, strategy := e.mutator.Mutate(seed)

		resp := e.transport.Send(mutated)
		e.stats.Iterations.Add(1)

		if resp.ConnErr {
			e.stats.ConnErrors.Add(1)
		} else if resp.Data == nil {
			e.stats.Timeouts.Add(1)
		} else {
			e.stats.Responses.Add(1)
		}

		finding := e.monitor.Analyze(resp, mutated, strategy.String(), iteration)
		if finding != nil {
			finding.InputHex = hex.EncodeToString(mutated)
			e.mu.Lock()
			e.findings = append(e.findings, finding)
			e.mu.Unlock()
			e.stats.Findings.Add(1)

			log.Printf("[!] FINDING #%d [%s] %s (iteration %d, strategy: %s)",
				finding.ID, finding.Severity, finding.Type, iteration, strategy)

			if e.cfg.Verbose {
				log.Printf("    input (%d bytes): %s", len(mutated), finding.InputHex)
			}
		}

		if e.cfg.Delay > 0 {
			time.Sleep(e.cfg.Delay)
		}
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
			log.Printf("progress: %d/%d iterations (%.1f/sec) | findings: %d | errors: %d | timeouts: %d",
				iters, e.cfg.Iterations, rate,
				e.stats.Findings.Load(),
				e.stats.ConnErrors.Load(),
				e.stats.Timeouts.Load())
		}
	}
}

func (e *Engine) finalize() error {
	elapsed := time.Since(e.stats.StartTime)
	iters := e.stats.Iterations.Load()

	log.Println("=== Fuzzing Complete ===")
	log.Printf("duration: %s", elapsed.Round(time.Millisecond))
	log.Printf("iterations: %d (%.1f/sec)", iters, float64(iters)/elapsed.Seconds())
	log.Printf("findings: %d", e.stats.Findings.Load())
	log.Printf("connection errors: %d", e.stats.ConnErrors.Load())
	log.Printf("timeouts: %d", e.stats.Timeouts.Load())
	log.Printf("responses: %d", e.stats.Responses.Load())

	e.mu.Lock()
	findings := make([]*monitor.Finding, len(e.findings))
	copy(findings, e.findings)
	e.mu.Unlock()

	if len(findings) > 0 {
		report := &reporter.Report{
			Target:      fmt.Sprintf("%s:%d", e.cfg.Host, e.cfg.Port),
			Protocol:    e.cfg.Protocol,
			StartTime:   e.stats.StartTime,
			EndTime:     time.Now(),
			Duration:    elapsed,
			Iterations:  iters,
			Findings:    findings,
			ConnErrors:  e.stats.ConnErrors.Load(),
			Timeouts:    e.stats.Timeouts.Load(),
			Responses:   e.stats.Responses.Load(),
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
