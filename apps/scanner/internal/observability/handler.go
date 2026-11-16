package observability

import (
	"context"
	"log/slog"
	"slices"

	"github.com/getsentry/sentry-go"
)

// Handler wraps a slog.Handler: every record is passed to the inner handler
// unchanged, and records at Error level or above are also sent to Sentry.
type Handler struct {
	inner slog.Handler
	hub   *sentry.Hub
	attrs []slog.Attr
	group string
}

// NewHandler reports Error records through hub (sentry.CurrentHub() when nil).
func NewHandler(inner slog.Handler, hub *sentry.Hub) *Handler {
	if hub == nil {
		hub = sentry.CurrentHub()
	}
	return &Handler{inner: inner, hub: hub}
}

// Enabled implements slog.Handler.
func (h *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= slog.LevelError || h.inner.Enabled(ctx, level)
}

// Handle implements slog.Handler.
func (h *Handler) Handle(ctx context.Context, rec slog.Record) error {
	if rec.Level >= slog.LevelError {
		CaptureLog(h.hub, rec, h.attrs)
	}
	if !h.inner.Enabled(ctx, rec.Level) {
		return nil
	}
	return h.inner.Handle(ctx, rec)
}

// WithAttrs implements slog.Handler.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clone := *h
	clone.inner = h.inner.WithAttrs(attrs)
	prefixed := make([]slog.Attr, 0, len(attrs))
	for _, a := range attrs {
		if h.group != "" {
			a.Key = h.group + "." + a.Key
		}
		prefixed = append(prefixed, a)
	}
	clone.attrs = append(slices.Clone(h.attrs), prefixed...)
	return &clone
}

// WithGroup implements slog.Handler.
func (h *Handler) WithGroup(name string) slog.Handler {
	clone := *h
	clone.inner = h.inner.WithGroup(name)
	if clone.group != "" {
		name = clone.group + "." + name
	}
	clone.group = name
	return &clone
}
