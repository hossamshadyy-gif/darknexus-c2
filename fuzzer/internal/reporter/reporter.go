package reporter

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/darknexus/fuzzer/internal/monitor"
)

type Report struct {
	Target     string             `json:"target"`
	Protocol   string             `json:"protocol"`
	StartTime  time.Time          `json:"start_time"`
	EndTime    time.Time          `json:"end_time"`
	Duration   time.Duration      `json:"duration"`
	Iterations int64              `json:"iterations"`
	Findings   []*monitor.Finding `json:"findings"`
	ConnErrors int64              `json:"connection_errors"`
	Timeouts   int64              `json:"timeouts"`
	Responses  int64              `json:"responses"`
}

type Reporter struct {
	outputDir string
}

func New(outputDir string) *Reporter {
	return &Reporter{outputDir: outputDir}
}

func (r *Reporter) Write(report *Report) error {
	if err := os.MkdirAll(r.outputDir, 0750); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	ts := report.StartTime.Format("20060102_150405")

	jsonPath := filepath.Join(r.outputDir, fmt.Sprintf("report_%s.json", ts))
	if err := r.writeJSON(jsonPath, report); err != nil {
		return err
	}
	log.Printf("JSON report written to %s", jsonPath)

	txtPath := filepath.Join(r.outputDir, fmt.Sprintf("report_%s.txt", ts))
	if err := r.writeText(txtPath, report); err != nil {
		return err
	}
	log.Printf("text report written to %s", txtPath)

	crashDir := filepath.Join(r.outputDir, "crashes")
	if err := os.MkdirAll(crashDir, 0750); err != nil {
		return fmt.Errorf("create crashes dir: %w", err)
	}

	for _, f := range report.Findings {
		if f.Severity >= monitor.SevHigh {
			crashPath := filepath.Join(crashDir, fmt.Sprintf("crash_%d_%s.bin", f.ID, f.Type))
			if err := os.WriteFile(crashPath, f.Input, 0640); err != nil {
				log.Printf("warning: failed to write crash input %d: %v", f.ID, err)
			}
		}
	}

	return nil
}

func (r *Reporter) writeJSON(path string, report *Report) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create JSON report: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("encode JSON report: %w", err)
	}
	return nil
}

func (r *Reporter) writeText(path string, report *Report) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create text report: %w", err)
	}
	defer f.Close()

	fmt.Fprintf(f, "╔══════════════════════════════════════════════════════╗\n")
	fmt.Fprintf(f, "║         DARKNEXUS PROTOCOL FUZZER REPORT            ║\n")
	fmt.Fprintf(f, "╚══════════════════════════════════════════════════════╝\n\n")
	fmt.Fprintf(f, "Target:      %s\n", report.Target)
	fmt.Fprintf(f, "Protocol:    %s\n", report.Protocol)
	fmt.Fprintf(f, "Start:       %s\n", report.StartTime.Format(time.RFC3339))
	fmt.Fprintf(f, "End:         %s\n", report.EndTime.Format(time.RFC3339))
	fmt.Fprintf(f, "Duration:    %s\n", report.Duration.Round(time.Millisecond))
	fmt.Fprintf(f, "Iterations:  %d\n", report.Iterations)
	fmt.Fprintf(f, "Findings:    %d\n", len(report.Findings))
	fmt.Fprintf(f, "Conn Errors: %d\n", report.ConnErrors)
	fmt.Fprintf(f, "Timeouts:    %d\n", report.Timeouts)
	fmt.Fprintf(f, "Responses:   %d\n\n", report.Responses)

	sevCounts := map[monitor.FindingSeverity]int{}
	for _, finding := range report.Findings {
		sevCounts[finding.Severity]++
	}

	fmt.Fprintf(f, "── Severity Summary ──\n")
	fmt.Fprintf(f, "  CRITICAL: %d\n", sevCounts[monitor.SevCritical])
	fmt.Fprintf(f, "  HIGH:     %d\n", sevCounts[monitor.SevHigh])
	fmt.Fprintf(f, "  MEDIUM:   %d\n", sevCounts[monitor.SevMedium])
	fmt.Fprintf(f, "  LOW:      %d\n", sevCounts[monitor.SevLow])
	fmt.Fprintf(f, "  INFO:     %d\n\n", sevCounts[monitor.SevInfo])

	for _, finding := range report.Findings {
		fmt.Fprintf(f, "── Finding #%d ──\n", finding.ID)
		fmt.Fprintf(f, "  Severity:    %s\n", finding.Severity)
		fmt.Fprintf(f, "  Type:        %s\n", finding.Type)
		fmt.Fprintf(f, "  Description: %s\n", finding.Description)
		fmt.Fprintf(f, "  Strategy:    %s\n", finding.Strategy)
		fmt.Fprintf(f, "  Iteration:   %d\n", finding.Iteration)
		fmt.Fprintf(f, "  Duration:    %s\n", finding.Duration)
		fmt.Fprintf(f, "  Input (%d bytes):\n", len(finding.Input))
		fmt.Fprintf(f, "    %s\n", hex.Dump(finding.Input))
		if finding.Response != nil {
			respPreview := finding.Response
			if len(respPreview) > 512 {
				respPreview = respPreview[:512]
			}
			fmt.Fprintf(f, "  Response (%d bytes, first 512):\n", len(finding.Response))
			fmt.Fprintf(f, "    %s\n", hex.Dump(respPreview))
		}
		fmt.Fprintln(f)
	}

	return nil
}
