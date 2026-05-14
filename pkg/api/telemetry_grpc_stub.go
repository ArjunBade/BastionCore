package api

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
)

// ProcessEvent mirrors the protobuf message.
type ProcessEvent struct {
	Timestamp       int64
	ProcessId       uint32
	ParentProcessId uint32
	ImagePath       string
	CommandLine     string
	EventType       string
}

// EventResponse mirrors the protobuf message.
type EventResponse struct {
	Success bool
}

// TelemetryClient is the client API for Telemetry service.
type TelemetryClient interface {
	SendEvent(ctx context.Context, in *ProcessEvent, opts ...grpc.CallOption) (*EventResponse, error)
}

type telemetryClient struct {
	cc *grpc.ClientConn
}

func NewTelemetryClient(cc *grpc.ClientConn) TelemetryClient {
	return &telemetryClient{cc}
}

func (c *telemetryClient) SendEvent(ctx context.Context, in *ProcessEvent, opts ...grpc.CallOption) (*EventResponse, error) {
	out := new(EventResponse)
	err := c.cc.Invoke(ctx, "/api.Telemetry/SendEvent", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TelemetryServer is the server API for Telemetry service.
type TelemetryServer interface {
	SendEvent(context.Context, *ProcessEvent) (*EventResponse, error)
}

// UnimplementedTelemetryServer can be embedded to have forward compatible implementations.
type UnimplementedTelemetryServer struct{}

func (*UnimplementedTelemetryServer) SendEvent(context.Context, *ProcessEvent) (*EventResponse, error) {
	return nil, fmt.Errorf("method SendEvent not implemented")
}

func RegisterTelemetryServer(s *grpc.Server, srv TelemetryServer) {
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: "api.Telemetry",
		HandlerType: (*TelemetryServer)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "SendEvent",
				Handler:    _Telemetry_SendEvent_Handler,
			},
		},
		Streams:  []grpc.StreamDesc{},
		Metadata: "pkg/api/telemetry.proto",
	}, srv)
}

func _Telemetry_SendEvent_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ProcessEvent)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TelemetryServer).SendEvent(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.Telemetry/SendEvent",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TelemetryServer).SendEvent(ctx, req.(*ProcessEvent))
	}
	return interceptor(ctx, in, info, handler)
}
