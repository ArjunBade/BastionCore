package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"edr-core/pkg/api"
)

type telemServer struct {
	api.UnimplementedTelemetryServer
}

func (s *telemServer) SendEvent(ctx context.Context, ev *api.ProcessEvent) (*api.EventResponse, error) {
	fmt.Printf("Received ProcessEvent: timestamp=%d pid=%d ppid=%d image=%s cmd=%s type=%s\n",
		ev.Timestamp, ev.ProcessId, ev.ParentProcessId, ev.ImagePath, ev.CommandLine, ev.EventType)
	return &api.EventResponse{Success: true}, nil
}

func (s *telemServer) SendHeartbeat(ctx context.Context, hb *api.HeartbeatEvent) (*api.EventResponse, error) {
	fmt.Printf("[💓] Heartbeat received from: %s\n", hb.AgentId)
	return &api.EventResponse{Success: true}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	// Load CA cert to verify client certificates
	caCert, err := os.ReadFile("certs/ca-cert.pem")
	if err != nil {
		log.Fatalf("failed to read CA cert: %v", err)
	}
	clientCAs := x509.NewCertPool()
	if ok := clientCAs.AppendCertsFromPEM(caCert); !ok {
		log.Fatalf("failed to append CA cert to client CA pool")
	}

	// Load server certificate and key
	serverCert, err := tls.LoadX509KeyPair("certs/server-cert.pem", "certs/server-key.pem")
	if err != nil {
		log.Fatalf("failed to load server cert/key: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	api.RegisterTelemetryServer(grpcServer, &telemServer{})

	log.Printf("gRPC server listening on :50051")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("gRPC server exited with error: %v", err)
	}
}
