package config

import (
	"encoding/json"
	"errors"
	"os"
	"time"
)

type Config struct {
	URL             string
	URLList         string
	RequestFile     string
	Threads         int
	Timeout         time.Duration
	Proxy           string
	Socks5Proxy     string
	RateLimit       int
	RateLimitBurst  int
	Retries         int
	RetryBackoff    time.Duration
	FollowRedirects bool
	Headers         map[string]string
	Cookies         map[string]string
	UserAgent       string
	OutputJSON      string
	OutputMarkdown  string
	OutputCSV       string
	OutputHTML      string
	SaveRequestsDir string
	SaveResponsesDir string
	ExportRawDir    string
	Resume          bool
	CheckpointFile  string
	ConfigFile      string
	NoTUI           bool
	LogJSON         bool
	MaxDepth        int
	BaseDepth       int
	MaxPayloads     int
	MaxBodySize     int64
	AutoThrottle    bool
}

func Default() Config {
	return Config{
		Threads:         120,
		Timeout:         10 * time.Second,
		RateLimit:       0,
		RateLimitBurst:  0,
		Retries:         2,
		RetryBackoff:    700 * time.Millisecond,
		FollowRedirects: true,
		UserAgent:       "TraversalX/1.0 (+https://github.com/hunter-0x7/Lfi-and-Path-traversal-Fuzzer)",
		CheckpointFile:  "traversalx.checkpoint.json",
		MaxDepth:        12,
		BaseDepth:       4,
		MaxPayloads:     6000,
		MaxBodySize:     2 * 1024 * 1024,
		AutoThrottle:    true,
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.URL == "" && c.URLList == "" && c.RequestFile == "" {
		return errors.New("must supply -u, -l, or -r")
	}
	if c.Threads <= 0 {
		return errors.New("threads must be > 0")
	}
	if c.Timeout <= 0 {
		return errors.New("timeout must be > 0")
	}
	if c.BaseDepth <= 0 || c.MaxDepth < c.BaseDepth {
		return errors.New("invalid depth settings")
	}
	return nil
}
