package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
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

// pendingCommand mirrors the JSON returned by GET /api/response/pending.
type pendingCommand struct {
	ID        string `json:"id"`
	Action    string `json:"action"`
	TargetPID int32  `json:"target_pid"`
}

// pollResponseCommands fetches and executes any pending response commands
// queued for this host via the server's REST control plane.
func pollResponseCommands(restAddr, hostname string) {
	endpoint := fmt.Sprintf("%s/api/response/pending?hostname=%s", restAddr, url.QueryEscape(hostname))
	resp, err := http.Get(endpoint)
	if err != nil {
		log.Printf("failed to poll pending commands: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}

	var cmds []pendingCommand
	if err := json.NewDecoder(resp.Body).Decode(&cmds); err != nil {
		log.Printf("failed to decode pending commands: %v", err)
		return
	}

	for _, c := range cmds {
		if c.Action != "KILL_PID" {
			continue
		}
		status := "EXECUTED"
		if err := process.TerminateProcess(uint32(c.TargetPID)); err != nil {
			log.Printf("failed to execute kill command id=%s pid=%d: %v", c.ID, c.TargetPID, err)
			status = "FAILED"
		} else {
			log.Printf("executed kill command id=%s pid=%d", c.ID, c.TargetPID)
		}
		reportCommandComplete(restAddr, c.ID, status)
	}
}

// reportCommandComplete marks a response command as EXECUTED or FAILED.
func reportCommandComplete(restAddr, id, status string) {
	body, _ := json.Marshal(map[string]string{"id": id, "status": status})
	resp, err := http.Post(restAddr+"/api/response/complete", "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("failed to report command completion id=%s: %v", id, err)
		return
	}
	resp.Body.Close()
}

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

		restAddr := os.Getenv("REST_ADDR")
		if restAddr == "" {
			restAddr = "http://localhost:8080"
		}

		for range ticker.C {
			hb := &api.HeartbeatEvent{
				AgentId:   hostname,
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

			// Poll the REST control plane for queued response commands.
			pollResponseCommands(restAddr, hostname)
		}
	}()

	// wait for interrupt to exit
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	<-sigs

	log.Println("shutting down agent")
}
