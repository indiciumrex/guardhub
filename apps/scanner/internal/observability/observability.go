// Package observability reports scanner errors to Sentry (or any Sentry-protocol
// server). It is completely OFF unless SENTRY_DSN is set. It sends errors only
// (no traces or profiles), tags every event service=scanner, and runs each
// event through Scrub so no request data, query strings, credentials, tokens,
// e-mail or IP addresses, or stack-frame variables leave the process (§9).
// Error-level slog records become events through Handler.
package observability

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/getsentry/sentry-go"
)

// Service is the value of the `service` tag on every scanner event.
const Service = "scanner"

// FlushTimeout bounds how long shutdown waits for queued events.
const FlushTimeout = 3 * time.Second

// Config is the error-tracking configuration (all optional).
type Config struct {
	DSN         string
	Environment string
	Release     string
}

// FromLookup reads SENTRY_DSN, SENTRY_ENVIRONMENT (default "production") and
// GUARDHUB_VERSION (the release) through lookup (os.LookupEnv in production).
func FromLookup(lookup func(string) (string, bool)) Config {
	get := func(key string) string {
		v, _ := lookup(key)
		return strings.TrimSpace(v)
	}
	cfg := Config{DSN: get("SENTRY_DSN"), Environment: get("SENTRY_ENVIRONMENT"), Release: get("GUARDHUB_VERSION")}
	if cfg.Environment == "" {
		cfg.Environment = "production"
	}
	return cfg
}

// Enabled reports whether a DSN is configured.
func (c Config) Enabled() bool { return c.DSN != "" }

// Options builds the SDK options. httpTransport may be nil (SDK default).
func (c Config) Options(httpTransport http.RoundTripper) sentry.ClientOptions {
	return sentry.ClientOptions{
		Dsn:              c.DSN,
		Environment:      c.Environment,
		Release:          c.Release,
		SendDefaultPII:   false,
		EnableTracing:    false,
		TracesSampleRate: 0,
		SampleRate:       1,
		BeforeSend:       func(e *sentry.Event, _ *sentry.EventHint) *sentry.Event { return Scrub(e) },
		BeforeBreadcrumb: func(b *sentry.Breadcrumb, _ *sentry.BreadcrumbHint) *sentry.Breadcrumb {
			return scrubBreadcrumb(b)
		},
		BeforeSendTransaction: func(*sentry.Event, *sentry.EventHint) *sentry.Event { return nil },
		Tags:                  map[string]string{"service": Service},
		HTTPTransport:         httpTransport,
	}
}

// Init starts error reporting. It returns false (and does nothing) without a DSN.
func Init(cfg Config) (bool, error) {
	if !cfg.Enabled() {
		return false, nil
	}
	if err := sentry.Init(cfg.Options(nil)); err != nil {
		return false, fmt.Errorf("sentry init: %w", err)
	}
	return true, nil
}

// Flush waits (bounded) for queued events; a no-op when reporting is off.
func Flush() { sentry.Flush(FlushTimeout) }

// statusRecorder observes the SDK's HTTP answers so the test command can
// report a rejected or unreachable endpoint instead of a silent success.
type statusRecorder struct {
	next     http.RoundTripper
	mu       sync.Mutex
	statuses []int
	errs     []error
}

func (r *statusRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.next.RoundTrip(req)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		r.errs = append(r.errs, err)
		return nil, err
	}
	r.statuses = append(r.statuses, resp.StatusCode)
	return resp, nil
}

func (r *statusRecorder) result() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.errs) > 0 {
		return fmt.Errorf("network error: %s", ScrubText(r.errs[0].Error()))
	}
	if len(r.statuses) == 0 {
		return errors.New("nothing was sent before the timeout")
	}
	for _, s := range r.statuses {
		if s < 200 || s > 299 {
			return fmt.Errorf("server answered HTTP %d", s)
		}
	}
	return nil
}

// SendTestEvent implements `scanner sentry-test`: it sends one test event with
// the production options and waits for the server's answer. Exit codes:
// 0 accepted, 1 delivery failed, 2 SENTRY_DSN not set.
func SendTestEvent(ctx context.Context, cfg Config, out io.Writer, base http.RoundTripper) int {
	if !cfg.Enabled() {
		_, _ = fmt.Fprintln(out, "SENTRY_DSN is not set; error tracking is off. Nothing was sent.")
		return 2
	}
	if base == nil {
		base = http.DefaultTransport
	}
	rec := &statusRecorder{next: base}
	client, err := sentry.NewClient(cfg.Options(rec))
	if err != nil {
		_, _ = fmt.Fprintf(out, "Delivery FAILED: invalid SENTRY_DSN (%s).\n", ScrubText(err.Error()))
		return 1
	}
	hub := sentry.NewHub(client, sentry.NewScope())
	id := hub.CaptureEvent(&sentry.Event{
		Level:   sentry.LevelError,
		Message: "GuardHub Sentry test event (service=" + Service + ")",
	})
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	hub.FlushWithContext(ctx)
	client.Close()
	if id == nil {
		_, _ = fmt.Fprintln(out, "Delivery FAILED: the SDK dropped the event.")
		return 1
	}
	if err := rec.result(); err != nil {
		_, _ = fmt.Fprintf(out, "Delivery FAILED (%s).\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(out, "Sent test event %s (service=%s); the server accepted it.\n", *id, Service)
	_, _ = fmt.Fprintln(out, "Find it in Sentry by searching for this event id.")
	return 0
}

// Load is FromLookup(os.LookupEnv).
func Load() Config { return FromLookup(os.LookupEnv) }

// CaptureLog turns one slog record (plus the handler's pre-bound attributes)
// into a Sentry event. The `err` attribute becomes the exception.
func CaptureLog(hub *sentry.Hub, rec slog.Record, bound []slog.Attr) {
	extra := map[string]interface{}{}
	var cause error
	add := func(a slog.Attr) {
		if a.Key == "err" {
			if e, ok := a.Value.Any().(error); ok {
				cause = e
				return
			}
		}
		extra[a.Key] = a.Value.Resolve().String()
	}
	for _, a := range bound {
		add(a)
	}
	rec.Attrs(func(a slog.Attr) bool {
		add(a)
		return true
	})
	delete(extra, "service") // already a tag
	event := &sentry.Event{
		Level:       sentry.LevelError,
		Message:     rec.Message,
		Contexts:    map[string]sentry.Context{"log": extra},
		Fingerprint: []string{rec.Message},
		Logger:      "slog",
	}
	if cause != nil {
		event.Exception = []sentry.Exception{{
			Type:       fmt.Sprintf("%T", cause),
			Value:      rec.Message + ": " + cause.Error(),
			Stacktrace: sentry.NewStacktrace(),
		}}
	}
	hub.CaptureEvent(event)
}
