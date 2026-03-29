package server

import (
	"io"
	"log"
	"time"

	pb "github.com/mdean75/ebpf-grpc-experiment/proto/stream"
)

type Server struct {
	pb.UnimplementedStreamServiceServer
	processingDelay time.Duration
}

func New(delay time.Duration) *Server {
	return &Server{processingDelay: delay}
}

// BiDiStream reads each incoming Message, optionally sleeps to simulate
// processing, and sends a response with the same id and a server timestamp.
func (s *Server) BiDiStream(stream pb.StreamService_BiDiStreamServer) error {
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		if s.processingDelay > 0 {
			time.Sleep(s.processingDelay)
		}

		resp := &pb.Message{
			Id:        msg.Id,
			Timestamp: time.Now().UnixNano(),
		}
		if err := stream.Send(resp); err != nil {
			log.Printf("send error for id=%s: %v", msg.Id, err)
			return err
		}
	}
}
