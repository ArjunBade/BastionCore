package main

import (
	"context"
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"

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

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	api.RegisterTelemetryServer(grpcServer, &telemServer{})

	log.Printf("gRPC server listening on :50051")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("gRPC server exited with error: %v", err)
	}
}
