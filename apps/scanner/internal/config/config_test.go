package config

import (
	"log/slog"
	"testing"
	"time"
)

func lookupFrom(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

func TestDefaults(t *testing.T) {
	cfg, err := FromLookup(lookupFrom(map[string]string{}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RequestTimeout != 10*time.Second || cfg.HostRPS != 4 || cfg.HostBurst != 2 ||
		cfg.MaxRequestsPerScan != 80 || cfg.Workers != 4 || cfg.CheckConcurrency != 3 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if cfg.LogLevel != slog.LevelInfo || cfg.RedisURL == "" || cfg.ConsumerName == "" {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if len(cfg.AllowPrivateHosts) != 0 {
		t.Fatalf("allowlist must be empty by default")
	}
}

func TestOverrides(t *testing.T) {
	cfg, err := FromLookup(lookupFrom(map[string]string{
		"REDIS_URL":                     "redis://redis:6379/0",
		"LOG_LEVEL":                     "debug",
		"SCANNER_REQUEST_TIMEOUT":       "5",
		"SCANNER_HOST_RPS":              "2.5",
		"SCANNER_MAX_REQUESTS_PER_SCAN": "40",
		"SCANNER_WORKERS":               "8",
		"SCANNER_CHECK_CONCURRENCY":     "2",
		"SCANNER_ALLOW_PRIVATE_HOSTS":   " demo-target , Localhost ,",
		"SCANNER_CONSUMER_NAME":         "scanner-1",
		"SCANNER_VERIFY_DEADLINE":       "1500ms",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RedisURL != "redis://redis:6379/0" || cfg.LogLevel != slog.LevelDebug ||
		cfg.RequestTimeout != 5*time.Second || cfg.HostRPS != 2.5 || cfg.MaxRequestsPerScan != 40 ||
		cfg.Workers != 8 || cfg.CheckConcurrency != 2 || cfg.ConsumerName != "scanner-1" ||
		cfg.VerifyDeadline != 1500*time.Millisecond {
		t.Fatalf("overrides not applied: %+v", cfg)
	}
	if len(cfg.AllowPrivateHosts) != 2 || cfg.AllowPrivateHosts[0] != "demo-target" || cfg.AllowPrivateHosts[1] != "localhost" {
		t.Fatalf("allowlist parsed wrong: %#v", cfg.AllowPrivateHosts)
	}
}

func TestInvalidValues(t *testing.T) {
	for k, v := range map[string]string{
		"SCANNER_HOST_RPS":        "-1",
		"SCANNER_WORKERS":         "0",
		"SCANNER_REQUEST_TIMEOUT": "abc",
		"LOG_LEVEL":               "loud",
	} {
		if _, err := FromLookup(lookupFrom(map[string]string{k: v})); err == nil {
			t.Errorf("%s=%q: expected error", k, v)
		}
	}
}
