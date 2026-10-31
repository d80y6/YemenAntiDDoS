package ingestion

import (
	"fmt"
	"log"
	"net"
	"time"

	"google.golang.org/grpc"

	pb "github.com/littlewolf9527/xsight/controller/internal/pb"
)

// Server wraps the gRPC server with lifecycle management.
type Server struct {
	grpcServer *grpc.Server
	handler    *GRPCHandler
	listener   net.Listener
}

func NewServer(handler *GRPCHandler) *Server {
	srv := grpc.NewServer()
	pb.RegisterXSightServiceServer(srv, handler)
	return &Server{
		grpcServer: srv,
		handler:    handler,
	}
}

// Serve starts the gRPC server on the given address. Blocks until stopped.
func (s *Server) Serve(addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("grpc listen %s: %w", addr, err)
	}
	s.listener = lis
	log.Printf("grpc: listening on %s", addr)
	return s.grpcServer.Serve(lis)
}

var grpcStopLimit = 10 * time.Second

// GracefulStop forces transport shutdown at the limit, then waits for handlers.
func (s *Server) GracefulStop() {
	log.Println("grpc: graceful stop")
	done := make(chan struct{})
	go func() { s.grpcServer.GracefulStop(); close(done) }()
	select {
	case <-done:
	case <-time.After(grpcStopLimit):
		log.Printf("WARN grpc: graceful stop exceeded %v, forcing stop", grpcStopLimit)
		s.grpcServer.Stop()
		<-done // Handlers must exit before the caller closes the sample pool.
	}
}
