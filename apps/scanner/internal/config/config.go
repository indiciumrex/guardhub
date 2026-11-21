// Package config loads the scanner settings from environment variables.
// It holds no secrets and has no defaults that point at real infrastructure
// other than the local Redis used by docker-compose. The safety-envelope
// defaults follow docs/architecture.md §3.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// Defaults from docs/architecture.md §3 (scanner safety envelope).
const (
	DefaultRedisURL           = "redis://localhost:6379/0"
	DefaultRequestTimeout     = 10 * time.Second
	DefaultHostRPS            = 4.0
	DefaultHostBurst          = 2
	DefaultMaxRequestsPerScan = 220
	DefaultWorkers            = 4
	DefaultCheckConcurrency   = 3
	DefaultScanDeadline       = 180 * time.Second
	MaxScanDeadline           = 300 * time.Second
	DefaultVerifyDeadline     = 20 * time.Second // below the API's 25 s wait, so the scanner always answers first
	DefaultShutdownTimeout    = 25 * time.Second
)

// Config is the complete scanner configuration.
type Config struct {
	RedisURL           string
	LogLevel           slog.Level
	ConsumerName       string
	RequestTimeout     time.Duration
	HostRPS            float64
	HostBurst          int
	MaxRequestsPerScan int
	Workers            int
	CheckConcurrency   int
	VerifyDeadline     time.Duration
	ShutdownTimeout    time.Duration
	// DNSServer is the recursive resolver for DNS record checks ("host:port");
	// empty = the system resolver (/etc/resolv.conf).
	DNSServer string
	// CTURL is the Certificate Transparency search endpoint of
	// subdomain_takeover (SCANNER_CT_URL): empty = crt.sh, "off" = none.
	CTURL string
	// AllowPrivateHosts are exact hostnames that bypass the dial-time IP
	// guard. It exists ONLY for the local e2e demo target.
	AllowPrivateHosts []string
}

// Load reads the configuration from the process environment.
func Load() (Config, error) {
	return FromLookup(os.LookupEnv)
}

// FromLookup reads the configuration through lookup (os.LookupEnv in
// production, a map in tests).
func FromLookup(lookup func(string) (string, bool)) (Config, error) {
	get := func(key string) string {
		v, ok := lookup(key)
		if !ok {
			return ""
		}
		return strings.TrimSpace(v)
	}

	cfg := Config{
		RedisURL:           DefaultRedisURL,
		LogLevel:           slog.LevelInfo,
		RequestTimeout:     DefaultRequestTimeout,
		HostRPS:            DefaultHostRPS,
		HostBurst:          DefaultHostBurst,
		MaxRequestsPerScan: DefaultMaxRequestsPerScan,
		Workers:            DefaultWorkers,
		CheckConcurrency:   DefaultCheckConcurrency,
		VerifyDeadline:     DefaultVerifyDeadline,
		ShutdownTimeout:    DefaultShutdownTimeout,
	}

	if v := get("REDIS_URL"); v != "" {
		cfg.RedisURL = v
	}
	if v := get("LOG_LEVEL"); v != "" {
		if err := cfg.LogLevel.UnmarshalText([]byte(v)); err != nil {
			return Config{}, fmt.Errorf("LOG_LEVEL: %w", err)
		}
	}

	var err error
	if cfg.RequestTimeout, err = durationVar(get("SCANNER_REQUEST_TIMEOUT"), cfg.RequestTimeout); err != nil {
		return Config{}, fmt.Errorf("SCANNER_REQUEST_TIMEOUT: %w", err)
	}
	if cfg.VerifyDeadline, err = durationVar(get("SCANNER_VERIFY_DEADLINE"), cfg.VerifyDeadline); err != nil {
		return Config{}, fmt.Errorf("SCANNER_VERIFY_DEADLINE: %w", err)
	}
	if cfg.ShutdownTimeout, err = durationVar(get("SCANNER_SHUTDOWN_TIMEOUT"), cfg.ShutdownTimeout); err != nil {
		return Config{}, fmt.Errorf("SCANNER_SHUTDOWN_TIMEOUT: %w", err)
	}
	if v := get("SCANNER_HOST_RPS"); v != "" {
		f, perr := strconv.ParseFloat(v, 64)
		if perr != nil || f <= 0 {
			return Config{}, fmt.Errorf("SCANNER_HOST_RPS: must be a positive number, got %q", v)
		}
		cfg.HostRPS = f
	}
	if cfg.HostBurst, err = intVar(get("SCANNER_HOST_BURST"), cfg.HostBurst); err != nil {
		return Config{}, fmt.Errorf("SCANNER_HOST_BURST: %w", err)
	}
	if cfg.MaxRequestsPerScan, err = intVar(get("SCANNER_MAX_REQUESTS_PER_SCAN"), cfg.MaxRequestsPerScan); err != nil {
		return Config{}, fmt.Errorf("SCANNER_MAX_REQUESTS_PER_SCAN: %w", err)
	}
	if cfg.Workers, err = intVar(get("SCANNER_WORKERS"), cfg.Workers); err != nil {
		return Config{}, fmt.Errorf("SCANNER_WORKERS: %w", err)
	}
	if cfg.CheckConcurrency, err = intVar(get("SCANNER_CHECK_CONCURRENCY"), cfg.CheckConcurrency); err != nil {
		return Config{}, fmt.Errorf("SCANNER_CHECK_CONCURRENCY: %w", err)
	}

	cfg.DNSServer = get("SCANNER_DNS_SERVER")

	cfg.CTURL = strings.TrimSpace(get("SCANNER_CT_URL"))
	if cfg.CTURL != "" && cfg.CTURL != "off" &&
		!strings.HasPrefix(cfg.CTURL, "https://") && !strings.HasPrefix(cfg.CTURL, "http://") {
		return Config{}, fmt.Errorf("SCANNER_CT_URL: must be an http(s) URL or \"off\", got %q", cfg.CTURL)
	}

	for _, h := range strings.Split(get("SCANNER_ALLOW_PRIVATE_HOSTS"), ",") {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			cfg.AllowPrivateHosts = append(cfg.AllowPrivateHosts, h)
		}
	}

	cfg.ConsumerName = get("SCANNER_CONSUMER_NAME")
	if cfg.ConsumerName == "" {
		host, herr := os.Hostname()
		if herr != nil || host == "" {
			host = "scanner"
		}
		cfg.ConsumerName = fmt.Sprintf("%s-%d", host, os.Getpid())
	}
	return cfg, nil
}

// durationVar accepts a Go duration ("10s", "1500ms") or a whole number of
// seconds ("10"). Empty means "use def".
func durationVar(v string, def time.Duration) (time.Duration, error) {
	if v == "" {
		return def, nil
	}
	if n, err := strconv.Atoi(v); err == nil {
		if n <= 0 {
			return 0, fmt.Errorf("must be positive, got %q", v)
		}
		return time.Duration(n) * time.Second, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q", v)
	}
	if d <= 0 {
		return 0, fmt.Errorf("must be positive, got %q", v)
	}
	return d, nil
}

func intVar(v string, def int) (int, error) {
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("must be a positive integer, got %q", v)
	}
	return n, nil
}
