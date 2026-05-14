package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"edr-core/pkg/telemetry"
)

func main() {
	serverAddr := flag.String("server", "localhost:50051", "gRPC server address")
	loop := flag.Bool("loop", false, "send sequence in a loop every 10s")
	flag.Parse()

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "real-agent"
	}

	for {
		if err := sendSequence(*serverAddr, hostname); err != nil {
			log.Printf("sequence send failed: %v", err)
		}
		if !*loop {
			break
		}
		time.Sleep(10 * time.Second)
	}
}

func sendSequence(serverAddr, hostname string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("failed to dial server: %w", err)
	}
	defer conn.Close()

	client := telemetry.NewEDRServiceClient(conn)
	stream, err := client.StreamEvents(context.Background())
	if err != nil {
		return fmt.Errorf("failed to open stream: %w", err)
	}

	ts := time.Now().UnixMilli()

	// cmd.exe starts (PID 1200)
	ev1 := &telemetry.Event{
		Hostname:  hostname,
		Timestamp: ts,
		EventData: &telemetry.Event_Process{
			Process: &telemetry.ProcessEvent{
				Pid:         1200,
				Ppid:        0,
				Executable:  "cmd.exe",
				CommandLine: "cmd.exe",
				User:        "USER",
				Action:      "START",
			},
		},
	}

	// powershell.exe starts as child of cmd.exe (PID 1201) with -EncodedCommand
	ev2 := &telemetry.Event{
		Hostname:  hostname,
		Timestamp: ts + 100,
		EventData: &telemetry.Event_Process{
			Process: &telemetry.ProcessEvent{
				Pid:         1201,
				Ppid:        1200,
				Executable:  "powershell.exe",
				CommandLine: "powershell.exe -EncodedCommand KABU...",
				User:        "USER",
				Action:      "START",
			},
		},
	}

	// network connection from PID 1201 to 185.220.101.45:4444
	ev3 := &telemetry.Event{
		Hostname:  hostname,
		Timestamp: ts + 200,
		EventData: &telemetry.Event_Network{
			Network: &telemetry.NetworkEvent{
				Pid:        1201,
				Protocol:   "TCP",
				LocalIp:    "10.0.2.15",
				RemoteIp:   "185.220.101.45",
				RemotePort: 4444,
			},
		},
	}

	// mimikatz starts (PID 1202)
	ev4 := &telemetry.Event{
		Hostname:  hostname,
		Timestamp: ts + 300,
		EventData: &telemetry.Event_Process{
			Process: &telemetry.ProcessEvent{
				Pid:         1202,
				Ppid:        1201,
				Executable:  "mimikatz.exe",
				CommandLine: "mimikatz.exe",
				User:        "USER",
				Action:      "START",
			},
		},
	}

	events := []*telemetry.Event{ev1, ev2, ev3, ev4}

	for _, e := range events {
		if err := stream.Send(e); err != nil {
			return fmt.Errorf("failed to send event: %w", err)
		}
	}

	resp, err := stream.CloseAndRecv()
	if err != nil {
		return fmt.Errorf("stream CloseAndRecv error: %w", err)
	}

	if resp.GetSuccess() {
		log.Printf("sequence sent successfully: %s", resp.GetMessage())
	} else {
		log.Printf("sequence sent but server returned failure: %s", resp.GetMessage())
	}

	return nil
}
