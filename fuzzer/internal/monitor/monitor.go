package monitor

import (
	"bytes"
	"log"
	"strings"
	"time"

	"github.com/darknexus/fuzzer/internal/transport"
)

type FindingSeverity int

const (
	SevInfo FindingSeverity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func (s FindingSeverity) String() string {
	switch s {
	case SevInfo:
		return "INFO"
	case SevLow:
		return "LOW"
	case SevMedium:
		return "MEDIUM"
	case SevHigh:
		return "HIGH"
	case SevCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

type Finding struct {
	ID          int            `json:"id"`
	Timestamp   time.Time      `json:"timestamp"`
	Severity    FindingSeverity `json:"severity"`
	Type        string         `json:"type"`
	Description string         `json:"description"`
	Input       []byte         `json:"input"`
	InputHex    string         `json:"input_hex"`
	Response    []byte         `json:"response,omitempty"`
	Strategy    string         `json:"strategy"`
	Iteration   int            `json:"iteration"`
	Duration    time.Duration  `json:"duration"`
}

type Monitor struct {
	verbose         bool
	findingID       int
	crashPatterns   []string
	errorPatterns   []string
	baselineResp    []byte
	baselineSet     bool
	connectionFails int
	maxConnFails    int
}

func New(verbose bool) *Monitor {
	return &Monitor{
		verbose:      verbose,
		maxConnFails: 10,
		crashPatterns: []string{
			"segmentation fault", "segfault", "sigsegv",
			"stack smashing", "buffer overflow",
			"abort", "core dumped",
			"panic", "fatal error",
			"access violation", "heap corruption",
		},
		errorPatterns: []string{
			"internal server error", "500",
			"bad request", "400",
			"stack trace", "traceback",
			"exception", "error:",
			"syntax error", "parse error",
		},
	}
}

func (m *Monitor) SetCrashPatterns(patterns []string) {
	m.crashPatterns = patterns
}

func (m *Monitor) SetErrorPatterns(patterns []string) {
	m.errorPatterns = patterns
}

func (m *Monitor) Analyze(resp *transport.Response, input []byte, strategy string, iteration int) *Finding {
	if resp.ConnErr {
		m.connectionFails++
		if m.connectionFails >= m.maxConnFails {
			m.findingID++
			return &Finding{
				ID:          m.findingID,
				Timestamp:   time.Now(),
				Severity:    SevCritical,
				Type:        "service_crash",
				Description: "Target service stopped accepting connections after repeated failures",
				Input:       input,
				Strategy:    strategy,
				Iteration:   iteration,
				Duration:    resp.Duration,
			}
		}
		return nil
	}
	m.connectionFails = 0

	if !m.baselineSet && resp.Data != nil {
		m.baselineResp = make([]byte, len(resp.Data))
		copy(m.baselineResp, resp.Data)
		m.baselineSet = true
		if m.verbose {
			log.Printf("baseline response captured (%d bytes)", len(resp.Data))
		}
	}

	if finding := m.checkCrash(resp, input, strategy, iteration); finding != nil {
		return finding
	}
	if finding := m.checkError(resp, input, strategy, iteration); finding != nil {
		return finding
	}
	if finding := m.checkAnomaly(resp, input, strategy, iteration); finding != nil {
		return finding
	}

	return nil
}

func (m *Monitor) checkCrash(resp *transport.Response, input []byte, strategy string, iteration int) *Finding {
	if resp.Data == nil {
		return nil
	}

	lower := strings.ToLower(string(resp.Data))
	for _, pattern := range m.crashPatterns {
		if strings.Contains(lower, pattern) {
			m.findingID++
			return &Finding{
				ID:          m.findingID,
				Timestamp:   time.Now(),
				Severity:    SevCritical,
				Type:        "crash_detected",
				Description: "Response contains crash indicator: " + pattern,
				Input:       input,
				Response:    resp.Data,
				Strategy:    strategy,
				Iteration:   iteration,
				Duration:    resp.Duration,
			}
		}
	}
	return nil
}

func (m *Monitor) checkError(resp *transport.Response, input []byte, strategy string, iteration int) *Finding {
	if resp.Data == nil {
		return nil
	}

	lower := strings.ToLower(string(resp.Data))
	for _, pattern := range m.errorPatterns {
		if strings.Contains(lower, pattern) {
			m.findingID++
			return &Finding{
				ID:          m.findingID,
				Timestamp:   time.Now(),
				Severity:    SevMedium,
				Type:        "error_response",
				Description: "Response contains error indicator: " + pattern,
				Input:       input,
				Response:    resp.Data,
				Strategy:    strategy,
				Iteration:   iteration,
				Duration:    resp.Duration,
			}
		}
	}
	return nil
}

func (m *Monitor) checkAnomaly(resp *transport.Response, input []byte, strategy string, iteration int) *Finding {
	if !m.baselineSet || resp.Data == nil {
		return nil
	}

	sizeDiff := len(resp.Data) - len(m.baselineResp)
	if sizeDiff < 0 {
		sizeDiff = -sizeDiff
	}

	if len(m.baselineResp) > 0 && float64(sizeDiff)/float64(len(m.baselineResp)) > 5.0 {
		m.findingID++
		return &Finding{
			ID:          m.findingID,
			Timestamp:   time.Now(),
			Severity:    SevLow,
			Type:        "response_size_anomaly",
			Description: "Response size differs significantly from baseline",
			Input:       input,
			Response:    resp.Data,
			Strategy:    strategy,
			Iteration:   iteration,
			Duration:    resp.Duration,
		}
	}

	if len(resp.Data) > 0 && len(m.baselineResp) > 0 && !bytes.Equal(resp.Data[:min(4, len(resp.Data))], m.baselineResp[:min(4, len(m.baselineResp))]) {
		if resp.Duration > 10*time.Second {
			m.findingID++
			return &Finding{
				ID:          m.findingID,
				Timestamp:   time.Now(),
				Severity:    SevMedium,
				Type:        "timing_anomaly",
				Description: "Response took significantly longer than expected",
				Input:       input,
				Response:    resp.Data,
				Strategy:    strategy,
				Iteration:   iteration,
				Duration:    resp.Duration,
			}
		}
	}

	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
