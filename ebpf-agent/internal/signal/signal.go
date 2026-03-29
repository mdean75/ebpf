// Package signal exposes an HTTP API that service-a polls to get per-connection
// health scores from the eBPF agent.
package signal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mdean75/ebpf-grpc-experiment/ebpf-agent/internal/tracker"
)

// ConnHealthResponse is the JSON shape returned by the health endpoints.
type ConnHealthResponse struct {
	Conn struct {
		Saddr string `json:"saddr"`
		Daddr string `json:"daddr"`
		Sport uint16 `json:"sport"`
		Dport uint16 `json:"dport"`
	} `json:"conn"`
	Score     float64 `json:"score"`
	Status    string  `json:"status"`
	LastEvent string  `json:"last_event"`
	UpdatedAt string  `json:"updated_at"`
}

// Server is the HTTP signal API server.
type Server struct {
	tracker *tracker.Tracker
	addr    string
}

func New(t *tracker.Tracker, addr string) *Server {
	return &Server{tracker: t, addr: addr}
}

func (s *Server) ListenAndServe() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health/all", s.handleAll)
	mux.HandleFunc("/health/", s.handleOne)
	srv := &http.Server{
		Addr:         s.addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	return srv.ListenAndServe()
}

// GET /health/all — returns all tracked connections
func (s *Server) handleAll(w http.ResponseWriter, r *http.Request) {
	conns := s.tracker.All()
	resp := make([]ConnHealthResponse, 0, len(conns))
	for _, c := range conns {
		resp = append(resp, toResponse(c))
	}
	writeJSON(w, resp)
}

// GET /health/{saddr}/{daddr}/{dport} — returns one connection
func (s *Server) handleOne(w http.ResponseWriter, r *http.Request) {
	// path: /health/<saddr>/<daddr>/<dport>
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/health/"), "/")
	if len(parts) != 3 {
		http.Error(w, "usage: /health/{saddr}/{daddr}/{dport}", http.StatusBadRequest)
		return
	}
	// We look up by daddr IP since that's what service-a matches on
	daddrIP := parts[1]
	var found *tracker.ConnectionHealth
	for _, c := range s.tracker.All() {
		if c.Key.DaddrIP() == daddrIP {
			copy := c
			found = &copy
			break
		}
	}
	if found == nil {
		http.Error(w, fmt.Sprintf("no connection to %s", daddrIP), http.StatusNotFound)
		return
	}
	writeJSON(w, toResponse(*found))
}

func toResponse(h tracker.ConnectionHealth) ConnHealthResponse {
	var r ConnHealthResponse
	r.Conn.Saddr = h.Key.DaddrIP() // intentional: report from service-a perspective
	r.Conn.Daddr = h.Key.DaddrIP()
	r.Conn.Sport = h.Key.Sport
	r.Conn.Dport = h.Key.Dport
	r.Score = h.Score
	r.Status = h.Status()
	r.LastEvent = lastEvent(h)
	r.UpdatedAt = h.UpdatedAt.Format(time.RFC3339Nano)
	return r
}

func lastEvent(h tracker.ConnectionHealth) string {
	if h.LastRTO.After(h.LastRetransmit) {
		return "rto"
	}
	if !h.LastRetransmit.IsZero() {
		return "retransmit"
	}
	if h.RTTSpikeCount > 0 {
		return "rtt_spike"
	}
	return ""
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, "encode error", http.StatusInternalServerError)
	}
}
