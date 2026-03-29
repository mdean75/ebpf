package health

import (
	"net/http"
	"sync/atomic"
)

// Handler manages the /health and /degraded HTTP endpoints.
// Service A can poll /health; /degraded is toggled during baseline experiments
// to simulate a detected failure without network faults.
type Handler struct {
	degraded atomic.Bool
}

func New() *Handler {
	return &Handler{}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/health", h.health)
	mux.HandleFunc("/degraded", h.toggleDegraded)
}

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	if h.degraded.Load() {
		http.Error(w, "degraded", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

// toggleDegraded flips the degraded flag on POST, reports current state on GET.
func (h *Handler) toggleDegraded(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.degraded.Store(!h.degraded.Load())
		if h.degraded.Load() {
			w.Write([]byte("degraded=true"))
		} else {
			w.Write([]byte("degraded=false"))
		}
	case http.MethodGet:
		if h.degraded.Load() {
			w.Write([]byte("degraded=true"))
		} else {
			w.Write([]byte("degraded=false"))
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
