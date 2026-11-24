// Package oobserver is the lab collaborator's handler (cmd/laboob): it
// records hits on /t/<token> and answers /interactions/<token>.
package oobserver

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
)

// Server records hits per token, at most max distinct tokens.
type Server struct {
	mu   sync.Mutex
	hits map[string]int
	max  int
}

// New returns a Server keeping at most max tokens.
func New(max int) *Server { return &Server{hits: map[string]int{}, max: max} }

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasPrefix(r.URL.Path, "/t/"):
		tok := strings.TrimPrefix(r.URL.Path, "/t/")
		if i := strings.IndexByte(tok, '/'); i >= 0 {
			tok = tok[:i]
		}
		if tok != "" && len(tok) <= 64 {
			s.mu.Lock()
			if _, ok := s.hits[tok]; ok || len(s.hits) < s.max {
				s.hits[tok]++
			}
			s.mu.Unlock()
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("guardhub lab collaborator\n"))
	case strings.HasPrefix(r.URL.Path, "/interactions/") && r.Method == http.MethodGet:
		tok := strings.TrimPrefix(r.URL.Path, "/interactions/")
		s.mu.Lock()
		n := s.hits[tok]
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"token": tok, "hits": n})
	default:
		http.NotFound(w, r)
	}
}
