// Package healthstream implements the gRPC HealthWatcher service.
// It fans out health state transitions from the tracker to all connected watchers.
package healthstream

import (
	"sync"

	"github.com/mdean75/ebpf-grpc-experiment/ebpf-agent/internal/tracker"
	pb "github.com/mdean75/ebpf-grpc-experiment/proto/health"
)

// Server implements pb.HealthWatcherServer.
type Server struct {
	pb.UnimplementedHealthWatcherServer

	mu   sync.Mutex
	subs map[chan *pb.HealthEvent]struct{}
}

// New creates a Server and starts a goroutine that fans out tracker events
// to all connected Watch clients.
func New(t *tracker.Tracker) *Server {
	s := &Server{
		subs: make(map[chan *pb.HealthEvent]struct{}),
	}
	go s.broadcast(t.Events())
	return s
}

func (s *Server) broadcast(events <-chan tracker.HealthTransition) {
	for ev := range events {
		pbEv := &pb.HealthEvent{
			Daddr:  ev.DaddrIP,
			Score:  ev.Score,
			Status: ev.Status,
		}
		s.mu.Lock()
		for ch := range s.subs {
			select {
			case ch <- pbEv:
			default: // slow consumer — drop rather than block
			}
		}
		s.mu.Unlock()
	}
}

// Watch streams health events to the caller until the client disconnects.
func (s *Server) Watch(_ *pb.WatchRequest, stream pb.HealthWatcher_WatchServer) error {
	ch := make(chan *pb.HealthEvent, 32)

	s.mu.Lock()
	s.subs[ch] = struct{}{}
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.subs, ch)
		s.mu.Unlock()
	}()

	for {
		select {
		case ev := <-ch:
			if err := stream.Send(ev); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}
