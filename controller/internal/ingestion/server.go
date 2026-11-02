package ingestion

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "github.com/d80y6/YemenDDoS/controller/internal/pb"
)

// Server wraps the gRPC server with lifecycle management. When cfg.TLS.Enabled
// is true the listener serves mutual TLS: every Node must present a client
// certificate whose chain terminates in the deployment CA.
type Server struct {
	grpcServer *grpc.Server
	handler    *GRPCHandler
	listener   net.Listener
	tls        *tls.Config
}

// NewServer builds the gRPC server. cfg may be nil, which keeps the historic
// plaintext behaviour (log a warning so operators do not deploy it by accident).
func NewServer(handler *GRPCHandler, cfg *tls.Config) *Server {
	var opts []grpc.ServerOption
	if cfg != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(cfg)))
		log.Println("grpc: mutual TLS enabled on Node listener")
	} else {
		log.Println("WARN grpc: serving PLAINTEXT gRPC — enable tls.enabled and provide ca_file/cert_file/key_file")
	}
	srv := grpc.NewServer(opts...)
	pb.RegisterXSightServiceServer(srv, handler)
	return &Server{
		grpcServer: srv,
		handler:    handler,
		tls:        cfg,
	}
}

// Serve starts the gRPC server on the given address. Blocks until stopped.
func (s *Server) Serve(addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("grpc listen %s: %w", addr, err)
	}
	s.listener = lis
	proto := "tcp"
	if s.tls != nil {
		proto = "tls"
	}
	log.Printf("grpc: listening on %s (%s)", addr, proto)
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
