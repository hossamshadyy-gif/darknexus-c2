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
	"github.com/darknexus/fuzzer/internal/corpus"
	"github.com/darknexus/fuzzer/internal/engine"
	"github.com/darknexus/fuzzer/internal/monitor"
	"github.com/darknexus/fuzzer/internal/mutator"
	"github.com/darknexus/fuzzer/internal/replay"
	"github.com/darknexus/fuzzer/internal/reporter"
	"github.com/darknexus/fuzzer/internal/transport"
)

const banner = `
    ____             __    _   __
   / __ \____ ______/ /__ / | / /__  _  ____  _______
  / / / / __ '/ ___/ //_//  |/ / _ \| |/_/ / / / ___/
 / /_/ / /_/ / /  / ,<  / /|  /  __/>  </ /_/ (__  )
/_____/\__,_/_/  /_/|_|/_/ |_/\___/_/|_|\__,_/____/
                                    Protocol Fuzzer
`

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	log.SetPrefix("[fuzzer] ")
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	switch os.Args[1] {
	case "fuzz":
		cmdFuzz(os.Args[2:])
	case "replay":
		cmdReplay(os.Args[2:])
	case "corpus":
		cmdCorpus(os.Args[2:])
	case "version":
		fmt.Println("darknexus-fuzzer v1.0.0")
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(banner)
	fmt.Println("Usage: darknexus-fuzzer <command> [options]")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  fuzz      Run the protocol fuzzer against a target")
	fmt.Println("  replay    Replay findings to verify reproducibility")
	fmt.Println("  corpus    Manage the fuzzing corpus (minimize, stats)")
	fmt.Println("  version   Print version information")
	fmt.Println("  help      Show this help message")
	fmt.Println()
	fmt.Println("Run 'darknexus-fuzzer <command> -h' for command-specific help.")
}

func cmdFuzz(args []string) {
	fs := flag.NewFlagSet("fuzz", flag.ExitOnError)
	host := fs.String("host", "127.0.0.1", "Target host")
	port := fs.Int("port", 0, "Target port")
	proto := fs.String("proto", "tcp", "Protocol: tcp, udp, tls")
	profile := fs.String("profile", "", "Path to fuzzing profile YAML")
	seedFile := fs.String("seed", "", "Path to seed corpus file or directory")
	corpusDir := fs.String("corpus", "", "Path to corpus directory (load/save)")
	timeout := fs.Duration("timeout", 5*time.Second, "Response timeout per probe")
	delay := fs.Duration("delay", 50*time.Millisecond, "Delay between probes")
	iterations := fs.Int("iterations", 10000, "Maximum fuzzing iterations")
	workers := fs.Int("workers", 4, "Number of concurrent fuzzing workers")
	outDir := fs.String("output", "fuzzer_results", "Output directory for findings")
	strategies := fs.String("strategies", "bitflip,byteinsert,boundary,format,repeat,truncate,havoc",
		"Comma-separated mutation strategies")
	enablePCAP := fs.Bool("pcap", false, "Enable PCAP traffic capture")
	poolSize := fs.Int("pool-size", 8, "Connection pool size for stateful protocols")
	verbose := fs.Bool("verbose", false, "Verbose logging")
	fs.Parse(args)

	if *port == 0 {
		fmt.Fprintf(os.Stderr, "Error: -port is required\n\n")
		fs.PrintDefaults()
		os.Exit(1)
	}

	fmt.Print(banner)

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
		EnablePCAP: *enablePCAP,
		CorpusDir:  *corpusDir,
		PoolSize:   *poolSize,
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

	if *corpusDir != "" {
		corp := corpus.New(*outDir, 4096)
		if err := corp.Load(*corpusDir); err != nil {
			log.Printf("warning: could not load corpus: %v", err)
		} else {
			for i := 0; i < corp.Size(); i++ {
				entry := corp.Get(i)
				if entry != nil {
					seeds = append(seeds, entry)
				}
			}
		}
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

	log.Printf("target: %s:%d (%s)", cfg.Host, cfg.Port, cfg.Protocol)
	log.Printf("strategies: %v | workers: %d | max iterations: %d",
		cfg.Strategies, cfg.Workers, cfg.Iterations)
	if cfg.EnablePCAP {
		log.Println("PCAP capture: enabled")
	}

	if err := eng.Run(); err != nil {
		log.Fatalf("fuzzer error: %v", err)
	}
}

func cmdReplay(args []string) {
	fs := flag.NewFlagSet("replay", flag.ExitOnError)
	host := fs.String("host", "127.0.0.1", "Target host")
	port := fs.Int("port", 0, "Target port")
	proto := fs.String("proto", "tcp", "Protocol: tcp, udp, tls")
	reportFile := fs.String("report", "", "Path to JSON report file with findings")
	hexInput := fs.String("hex", "", "Hex-encoded input to replay directly")
	timeout := fs.Duration("timeout", 5*time.Second, "Response timeout")
	delay := fs.Duration("delay", 1*time.Second, "Delay between replay attempts")
	attempts := fs.Int("attempts", 3, "Number of replay attempts per finding")
	outFile := fs.String("output", "replay_results.json", "Output file for replay results")
	verbose := fs.Bool("verbose", false, "Verbose logging")
	fs.Parse(args)

	if *port == 0 {
		fmt.Fprintf(os.Stderr, "Error: -port is required\n\n")
		fs.PrintDefaults()
		os.Exit(1)
	}

	if *reportFile == "" && *hexInput == "" {
		fmt.Fprintf(os.Stderr, "Error: -report or -hex is required\n\n")
		fs.PrintDefaults()
		os.Exit(1)
	}

	trans, err := transport.New(*proto, *host, *port, *timeout)
	if err != nil {
		log.Fatalf("failed to create transport: %v", err)
	}

	mon := monitor.New(*verbose)
	rep := replay.New(trans, mon, *delay, *attempts, *verbose)

	var results []*replay.ReplayResult

	if *hexInput != "" {
		result := rep.ReplayFromHex(*hexInput)
		if result != nil {
			results = append(results, result)
		}
	} else {
		var err error
		results, err = rep.ReplayFromFile(*reportFile)
		if err != nil {
			log.Fatalf("replay error: %v", err)
		}
	}

	if err := replay.WriteReplayResults(*outFile, results); err != nil {
		log.Fatalf("failed to write results: %v", err)
	}

	reproduced := 0
	for _, r := range results {
		if r.Reproduced {
			reproduced++
		}
	}

	log.Printf("replay complete: %d/%d findings reproduced", reproduced, len(results))
	log.Printf("results written to %s", *outFile)
}

func cmdCorpus(args []string) {
	fs := flag.NewFlagSet("corpus", flag.ExitOnError)
	dir := fs.String("dir", "", "Corpus directory")
	action := fs.String("action", "stats", "Action: stats, minimize, merge")
	mergeFrom := fs.String("merge-from", "", "Directory to merge corpus entries from")
	fs.Parse(args)

	if *dir == "" {
		fmt.Fprintf(os.Stderr, "Error: -dir is required\n\n")
		fs.PrintDefaults()
		os.Exit(1)
	}

	corp := corpus.New(*dir, 4096)
	if err := corp.Load(*dir); err != nil {
		log.Fatalf("failed to load corpus: %v", err)
	}

	switch *action {
	case "stats":
		log.Printf("corpus entries: %d", corp.Size())
		log.Printf("coverage paths: %d", corp.CoverageCount())

	case "minimize":
		removed := corp.Minimize()
		log.Printf("removed %d redundant entries", removed)
		if err := corp.Save(); err != nil {
			log.Fatalf("failed to save minimized corpus: %v", err)
		}

	case "merge":
		if *mergeFrom == "" {
			log.Fatal("-merge-from is required for merge action")
		}
		before := corp.Size()
		if err := corp.Load(*mergeFrom); err != nil {
			log.Fatalf("failed to load merge source: %v", err)
		}
		added := corp.Size() - before
		log.Printf("merged %d new entries", added)
		if err := corp.Save(); err != nil {
			log.Fatalf("failed to save merged corpus: %v", err)
		}

	default:
		log.Fatalf("unknown action: %s", *action)
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
