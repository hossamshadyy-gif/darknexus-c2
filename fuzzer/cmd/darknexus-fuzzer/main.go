package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/darknexus/fuzzer/internal/config"
	"github.com/darknexus/fuzzer/internal/engine"
	"github.com/darknexus/fuzzer/internal/monitor"
	"github.com/darknexus/fuzzer/internal/mutator"
	"github.com/darknexus/fuzzer/internal/reporter"
	"github.com/darknexus/fuzzer/internal/transport"
)

func main() {
	host := flag.String("host", "127.0.0.1", "Target host")
	port := flag.Int("port", 0, "Target port")
	proto := flag.String("proto", "tcp", "Protocol: tcp, udp, tls")
	profile := flag.String("profile", "", "Path to fuzzing profile YAML")
	seedFile := flag.String("seed", "", "Path to seed corpus file or directory")
	timeout := flag.Duration("timeout", 5*time.Second, "Response timeout per probe")
	delay := flag.Duration("delay", 50*time.Millisecond, "Delay between probes")
	iterations := flag.Int("iterations", 10000, "Maximum fuzzing iterations")
	workers := flag.Int("workers", 4, "Number of concurrent fuzzing workers")
	outDir := flag.String("output", "fuzzer_results", "Output directory for findings")
	strategies := flag.String("strategies", "bitflip,byteinsert,boundary,format,repeat,truncate",
		"Comma-separated mutation strategies")
	verbose := flag.Bool("verbose", false, "Verbose logging")
	flag.Parse()

	if *port == 0 {
		fmt.Fprintf(os.Stderr, "Usage: darknexus-fuzzer -host <host> -port <port> [options]\n\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	log.SetPrefix("[fuzzer] ")
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	cfg := &config.FuzzerConfig{
		Host:       *host,
		Port:       *port,
		Protocol:   *proto,
		Timeout:    *timeout,
		Delay:      *delay,
		Iterations: *iterations,
		Workers:    *workers,
		OutputDir:  *outDir,
		Verbose:    *verbose,
		Strategies: parseStrategies(*strategies),
	}

	if *profile != "" {
		profileCfg, err := config.LoadProfile(*profile)
		if err != nil {
			log.Fatalf("failed to load profile: %v", err)
		}
		cfg.Profile = profileCfg
	}

	seeds, err := loadSeeds(*seedFile)
	if err != nil {
		log.Fatalf("failed to load seeds: %v", err)
	}
	if len(seeds) == 0 {
		seeds = defaultSeeds(cfg.Protocol)
	}

	trans, err := transport.New(cfg.Protocol, cfg.Host, cfg.Port, cfg.Timeout)
	if err != nil {
		log.Fatalf("failed to create transport: %v", err)
	}

	mut := mutator.New(cfg.Strategies)
	mon := monitor.New(cfg.Verbose)
	rep := reporter.New(cfg.OutputDir)

	eng := engine.New(cfg, trans, mut, mon, rep, seeds)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("interrupt received, generating report...")
		eng.Stop()
	}()

	log.Printf("starting fuzzer against %s:%d (%s)", cfg.Host, cfg.Port, cfg.Protocol)
	log.Printf("strategies: %v | workers: %d | max iterations: %d",
		cfg.Strategies, cfg.Workers, cfg.Iterations)

	if err := eng.Run(); err != nil {
		log.Fatalf("fuzzer error: %v", err)
	}
}

func parseStrategies(s string) []mutator.Strategy {
	var strats []mutator.Strategy
	for _, name := range strings.Split(s, ",") {
		name = strings.TrimSpace(name)
		if st, ok := mutator.StrategyFromName(name); ok {
			strats = append(strats, st)
		}
	}
	if len(strats) == 0 {
		return mutator.DefaultStrategies()
	}
	return strats
}

func loadSeeds(path string) ([][]byte, error) {
	if path == "" {
		return nil, nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("seed path: %w", err)
	}

	if !info.IsDir() {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read seed: %w", err)
		}
		return [][]byte{data}, nil
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("read seed dir: %w", err)
	}

	var seeds [][]byte
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(path + "/" + e.Name())
		if err != nil {
			log.Printf("warning: skipping seed %s: %v", e.Name(), err)
			continue
		}
		seeds = append(seeds, data)
	}
	return seeds, nil
}

func defaultSeeds(proto string) [][]byte {
	switch proto {
	case "udp":
		return [][]byte{
			[]byte("\x00\x00\x00\x00"),
			[]byte("\xff\xff\xff\xff"),
			{0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		}
	default:
		return [][]byte{
			[]byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"),
			[]byte(`{"type":"checkin","id":"test"}`),
			[]byte("\x00\x00\x00\x04PING"),
			{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00},
		}
	}
}
