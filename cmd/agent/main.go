package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"edr-core/pkg/api"
	"edr-core/pkg/etw"
	"edr-core/pkg/process"
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

	serverAddr := os.Getenv("SERVER_ADDR")
	if serverAddr == "" {
		serverAddr = "localhost:50051"
	}

	conn, err := grpc.Dial(serverAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("failed to dial server: %v", err)
	}
	defer conn.Close()

	client := api.NewTelemetryClient(conn)

	// process start/terminate tracking
	var mu sync.Mutex
	seen := map[uint32]time.Time{}

	callback := func(pi etw.ProcessInfo) {
		mu.Lock()
		_, existed := seen[pi.ProcessID]
		seen[pi.ProcessID] = time.Now()
		mu.Unlock()

		ev := &api.ProcessEvent{
			Timestamp:       time.Now().UnixMilli(),
			ProcessId:       pi.ProcessID,
			ParentProcessId: pi.ParentProcessID,
			ImagePath:       pi.ImageName,
			CommandLine:     pi.CommandLine,
			EventType:       "START",
		}

		if existed {
			// already seen; send heartbeat-style update as START (keep simple)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if _, err := client.SendEvent(ctx, ev); err != nil {
			log.Printf("failed to send event: %v", err)
		} else {
			log.Printf("sent START event pid=%d", pi.ProcessID)
		}
	}

	if err := etw.StartWatching(callback); err != nil {
		log.Fatalf("failed to start watcher: %v", err)
	}

	networkCallback := func(ni etw.NetworkInfo) {
		ev := &api.NetworkEvent{
			Timestamp:  time.Now().UnixMilli(),
			ProcessId:  ni.ProcessID,
			SourceIp:   ni.SourceIP,
			SourcePort: ni.SourcePort,
			DestIp:     ni.DestIP,
			DestPort:   ni.DestPort,
			Protocol:   ni.Protocol,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if _, err := client.SendNetworkEvent(ctx, ev); err != nil {
			log.Printf("failed to send network event: %v", err)
		} else {
			log.Printf("sent network event pid=%d dest=%s:%d", ni.ProcessID, ni.DestIP, ni.DestPort)
		}
	}

	go func() {
		if err := etw.StartNetworkWatching(networkCallback); err != nil {
			log.Printf("failed to start network watcher: %v", err)
		}
	}()

	// background cleaner to emit TERMINATE when processes are not seen
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			now := time.Now()
			mu.Lock()
			for pid, last := range seen {
				if now.Sub(last) > 8*time.Second {
					// emit TERMINATE
					tev := &api.ProcessEvent{
						Timestamp:       time.Now().UnixMilli(),
						ProcessId:       pid,
						ParentProcessId: 0,
						ImagePath:       "",
						CommandLine:     "",
						EventType:       "TERMINATE",
					}
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					if _, err := client.SendEvent(ctx, tev); err != nil {
						log.Printf("failed to send terminate for pid=%d: %v", pid, err)
					} else {
						log.Printf("sent TERMINATE event pid=%d", pid)
					}
					cancel()
					delete(seen, pid)
				}
			}
			mu.Unlock()
		}
	}()

	// heartbeat goroutine
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		hostname, _ := os.Hostname()

		for range ticker.C {
			hb := &api.HeartbeatEvent{
				AgentId:   hostname,
				Status:    "ONLINE",
				Timestamp: time.Now().UnixMilli(),
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			resp, err := client.SendHeartbeat(ctx, hb)
			if err != nil {
				log.Printf("failed to send heartbeat: %v", err)
			} else {
				log.Println("[+] Heartbeat sent")
				if resp != nil && resp.Action == "KILL" {
					if err := process.TerminateProcess(resp.TargetPid); err != nil {
						log.Printf("failed to execute kill order for pid=%d: %v", resp.TargetPid, err)
					} else {
						log.Printf("executed server kill order for pid=%d", resp.TargetPid)
					}
				}
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
