package replay

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/darknexus/fuzzer/internal/monitor"
	"github.com/darknexus/fuzzer/internal/transport"
)

type ReplayResult struct {
	Finding      *monitor.Finding
	Reproduced   bool
	Attempts     int
	OrigResponse []byte
	NewResponse  []byte
	Consistent   bool
}

type Replayer struct {
	transport transport.Transport
	monitor   *monitor.Monitor
	delay     time.Duration
	attempts  int
	verbose   bool
}

func New(trans transport.Transport, mon *monitor.Monitor, delay time.Duration, attempts int, verbose bool) *Replayer {
	if attempts <= 0 {
		attempts = 3
	}
	return &Replayer{
		transport: trans,
		monitor:   mon,
		delay:     delay,
		attempts:  attempts,
		verbose:   verbose,
	}
}

func (r *Replayer) ReplayFinding(finding *monitor.Finding) *ReplayResult {
	result := &ReplayResult{
		Finding:      finding,
		OrigResponse: finding.Response,
	}

	log.Printf("[replay] reproducing finding #%d (%s)", finding.ID, finding.Type)

	reproduced := 0
	for i := 0; i < r.attempts; i++ {
		resp := r.transport.Send(finding.Input)
		result.Attempts++

		newFinding := r.monitor.Analyze(resp, finding.Input, finding.Strategy, finding.Iteration)
		if newFinding != nil && newFinding.Type == finding.Type {
			reproduced++
			result.NewResponse = resp.Data
		}

		if r.verbose {
			if newFinding != nil {
				log.Printf("[replay]   attempt %d/%d: reproduced (%s)", i+1, r.attempts, newFinding.Type)
			} else {
				log.Printf("[replay]   attempt %d/%d: not reproduced", i+1, r.attempts)
			}
		}

		if i < r.attempts-1 {
			time.Sleep(r.delay)
		}
	}

	result.Reproduced = reproduced > 0
	result.Consistent = reproduced == r.attempts

	if result.Reproduced {
		log.Printf("[replay] finding #%d REPRODUCED (%d/%d attempts, consistent: %v)",
			finding.ID, reproduced, r.attempts, result.Consistent)
	} else {
		log.Printf("[replay] finding #%d could not be reproduced", finding.ID)
	}

	return result
}

func (r *Replayer) ReplayAll(findings []*monitor.Finding) []*ReplayResult {
	var results []*ReplayResult
	for _, f := range findings {
		result := r.ReplayFinding(f)
		results = append(results, result)
		time.Sleep(r.delay)
	}
	return results
}

func (r *Replayer) ReplayFromFile(path string) ([]*ReplayResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read findings file: %w", err)
	}

	var report struct {
		Findings []*monitor.Finding `json:"findings"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("parse findings: %w", err)
	}

	log.Printf("[replay] loaded %d findings from %s", len(report.Findings), path)
	return r.ReplayAll(report.Findings), nil
}

func (r *Replayer) ReplayFromHex(hexInput string) *ReplayResult {
	input, err := hex.DecodeString(hexInput)
	if err != nil {
		log.Printf("[replay] invalid hex input: %v", err)
		return nil
	}

	finding := &monitor.Finding{
		Input:    input,
		Strategy: "manual",
	}

	return r.ReplayFinding(finding)
}

func WriteReplayResults(path string, results []*ReplayResult) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create replay report: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")

	type replayReport struct {
		Timestamp  time.Time       `json:"timestamp"`
		Total      int             `json:"total"`
		Reproduced int             `json:"reproduced"`
		Consistent int             `json:"consistent"`
		Results    []*ReplayResult `json:"results"`
	}

	report := &replayReport{
		Timestamp: time.Now(),
		Total:     len(results),
		Results:   results,
	}

	for _, r := range results {
		if r.Reproduced {
			report.Reproduced++
		}
		if r.Consistent {
			report.Consistent++
		}
	}

	return enc.Encode(report)
}
