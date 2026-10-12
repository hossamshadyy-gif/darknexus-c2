package profile

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Profile represents a malleable C2 traffic profile
type Profile struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`

	HTTP struct {
		Checkin struct {
			URI     string            `yaml:"uri"`
			Method  string            `yaml:"method"`
			Headers map[string]string `yaml:"headers"`
		} `yaml:"checkin"`

		Result struct {
			URI     string            `yaml:"uri"`
			Method  string            `yaml:"method"`
			Headers map[string]string `yaml:"headers"`
		} `yaml:"result"`

		DefaultPage struct {
			Status  int               `yaml:"status"`
			Headers map[string]string `yaml:"headers"`
			Body    string            `yaml:"body"`
		} `yaml:"default_page"`
	} `yaml:"http"`

	UserAgents []string `yaml:"user_agents"`

	Beacon struct {
		Sleep      int    `yaml:"sleep"`
		Jitter     int    `yaml:"jitter"`
		MaxRetries int    `yaml:"max_retries"`
		KillDate   string `yaml:"kill_date"`
	} `yaml:"beacon"`

	TLS struct {
		Cert string `yaml:"cert"`
		Key  string `yaml:"key"`
	} `yaml:"tls"`
}

// Load reads a profile YAML from disk
func Load(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profile %s: %w", path, err)
	}

	var p Profile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse profile %s: %w", path, err)
	}

	// defaults
	if p.Beacon.Sleep == 0 {
		p.Beacon.Sleep = 5
	}
	if p.Beacon.Jitter == 0 {
		p.Beacon.Jitter = 20
	}
	if p.Beacon.MaxRetries == 0 {
		p.Beacon.MaxRetries = 10
	}

	return &p, nil
}

// ListProfiles returns all .yaml files in a directory
func ListProfiles(dir string) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	return matches, nil
}
