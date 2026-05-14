package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"edr-core/pkg/api"
	"edr-core/pkg/etw"
)

func main() {
	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("failed to dial server: %v", err)
	}
	defer conn.Close()

	client := api.NewTelemetryClient(conn)

	callback := func(pi etw.ProcessInfo) {
		ev := &api.ProcessEvent{
			Timestamp:       time.Now().UnixMilli(),
			ProcessId:       pi.ProcessID,
			ParentProcessId: pi.ParentProcessID,
			ImagePath:       pi.ImageName,
			CommandLine:     pi.CommandLine,
			EventType:       "process_create",
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if _, err := client.SendEvent(ctx, ev); err != nil {
			log.Printf("failed to send event: %v", err)
		} else {
			log.Printf("sent event pid=%d", pi.ProcessID)
		}
	}

	if err := etw.StartWatching(callback); err != nil {
		log.Fatalf("failed to start watcher: %v", err)
	}

	// wait for interrupt to exit
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	<-sigs

	log.Println("shutting down agent")
}
