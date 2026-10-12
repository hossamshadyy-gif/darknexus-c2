package config

import (
	"fmt"
	"os"
	"time"

	"github.com/darknexus/fuzzer/internal/mutator"
	"gopkg.in/yaml.v3"
)

type FuzzerConfig struct {
	Host       string
	Port       int
	Protocol   string
	Timeout    time.Duration
	Delay      time.Duration
	Iterations int
	Workers    int
	OutputDir  string
	Verbose    bool
	Strategies []mutator.Strategy
	Profile    *FuzzProfile
}

type FuzzProfile struct {
	Name     string          `yaml:"name"`
	Protocol ProtocolProfile `yaml:"protocol"`
	Mutation MutationProfile `yaml:"mutation"`
	Monitor  MonitorProfile  `yaml:"monitor"`
}

type ProtocolProfile struct {
	Type        string            `yaml:"type"`
	Handshake   []string          `yaml:"handshake"`
	Delimiter   string            `yaml:"delimiter"`
	LengthField *LengthFieldSpec  `yaml:"length_field"`
	Headers     map[string]string `yaml:"headers"`
}

type LengthFieldSpec struct {
	Offset    int    `yaml:"offset"`
	Size      int    `yaml:"size"`
	ByteOrder string `yaml:"byte_order"`
	Includes  string `yaml:"includes"`
}

type MutationProfile struct {
	MaxSize    int      `yaml:"max_size"`
	Strategies []string `yaml:"strategies"`
	Dictionary []string `yaml:"dictionary"`
}

type MonitorProfile struct {
	CrashPatterns  []string `yaml:"crash_patterns"`
	ErrorPatterns  []string `yaml:"error_patterns"`
	SuccessPattern string   `yaml:"success_pattern"`
}

func LoadProfile(path string) (*FuzzProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profile: %w", err)
	}

	var profile FuzzProfile
	if err := yaml.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("parse profile: %w", err)
	}

	return &profile, nil
}
