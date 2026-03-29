package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/mdean75/ebpf-grpc-experiment/service-b/config"
	"github.com/mdean75/ebpf-grpc-experiment/service-b/internal/health"
	"github.com/mdean75/ebpf-grpc-experiment/service-b/internal/server"

	pb "github.com/mdean75/ebpf-grpc-experiment/proto/stream"
	"google.golang.org/grpc"
)

func main() {
	cfg := config.Load()

	// gRPC server — plain TCP, no TLS (nginx handles TLS in stream proxy mode)
	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", cfg.GRPCPort))
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterStreamServiceServer(grpcServer, server.New(cfg.ProcessingDelay))

	// HTTP health server
	mux := http.NewServeMux()
	healthHandler := health.New()
	healthHandler.Register(mux)
	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%s", cfg.HealthPort),
		Handler: mux,
	}

	// Start gRPC
	go func() {
		log.Printf("gRPC listening on :%s (plain TCP)", cfg.GRPCPort)
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("grpc serve: %v", err)
		}
	}()

	// Start HTTP health endpoint
	go func() {
		log.Printf("health HTTP listening on :%s", cfg.HealthPort)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http serve: %v", err)
		}
	}()

	// Wait for signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("shutting down")
	grpcServer.GracefulStop()
}
