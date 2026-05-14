package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"edr-core/pkg/api"
	"edr-core/pkg/etw"
)

func main() {
	// Load CA cert to verify server certificate
	caCert, err := os.ReadFile("certs/ca-cert.pem")
	if err != nil {
		log.Fatalf("failed to read CA cert: %v", err)
	}
	roots := x509.NewCertPool()
	if ok := roots.AppendCertsFromPEM(caCert); !ok {
		log.Fatalf("failed to append CA cert to pool")
	}

	// Load agent certificate and key to present to server
	clientCert, err := tls.LoadX509KeyPair("certs/agent-cert.pem", "certs/agent-key.pem")
	if err != nil {
		log.Fatalf("failed to load client cert/key: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      roots,
	}

	creds := credentials.NewTLS(tlsConfig)

	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(creds))
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

	// heartbeat goroutine
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			hb := &api.HeartbeatEvent{
				AgentId:   "agent-007",
				Status:    "ONLINE",
				Timestamp: time.Now().UnixMilli(),
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if _, err := client.SendHeartbeat(ctx, hb); err != nil {
				log.Printf("failed to send heartbeat: %v", err)
			} else {
				log.Println("[+] Heartbeat sent")
			}
			cancel()
		}
	}()

	// wait for interrupt to exit
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	<-sigs

	log.Println("shutting down agent")
}
